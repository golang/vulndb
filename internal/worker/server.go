// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cloud.google.com/go/errorreporting"
	"github.com/google/safehtml/template"
	"golang.org/x/exp/event"
	"golang.org/x/sync/errgroup"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"

	mexporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric"
	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	gcppropagator "github.com/GoogleCloudPlatform/opentelemetry-operations-go/propagator"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	eotel "golang.org/x/exp/event/otel"
)

const pkgsiteURL = "https://pkg.go.dev"

var staticPath = template.TrustedSourceFromConstant("internal/worker/static")

type Server struct {
	cfg           Config
	indexTemplate *template.Template
	issueClient   issues.Client
	traceHandler  event.Handler
	metricHandler event.Handler
	propagator    propagation.TextMapPropagator
	afterRequest  func()
}

func NewServer(ctx context.Context, cfg Config) (_ *Server, err error) {
	defer derrors.Wrap(&err, "NewServer(%q)", cfg.Namespace)

	s := &Server{cfg: cfg}

	tracerProvider, meterProvider, err := initOpenTelemetry(cfg.Project)
	if err != nil {
		return nil, err
	}
	s.traceHandler = eotel.NewTraceHandler(tracerProvider.Tracer("vulndb-worker"))
	s.metricHandler = eotel.NewMetricHandler(meterProvider.Meter("vulndb-worker"))

	s.afterRequest = func() { tracerProvider.ForceFlush(ctx) }
	// The propagator extracts incoming trace IDs so that we can connect our trace spans
	// to the incoming ones constructed by Cloud Run.
	s.propagator = propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
		gcppropagator.New(),
	)

	if cfg.UseErrorReporting {
		reportingClient, err := errorreporting.NewClient(ctx, cfg.Project, errorreporting.Config{
			ServiceName: serviceID,
			OnError: func(err error) {
				log.Errorf(ctx, "Error reporting failed: %v", err)
			},
		})
		if err != nil {
			return nil, err
		}
		derrors.SetReportingClient(reportingClient)
	}
	if cfg.IssueRepo != "" {
		owner, repoName, err := gitrepo.ParseGitHubRepo(cfg.IssueRepo)
		if err != nil {
			return nil, err
		}
		s.issueClient = issues.NewGitHubClient(owner, repoName, cfg.GitHubAccessToken)
		log.Infof(ctx, "issue creation enabled for repo %s", cfg.IssueRepo)
	} else {
		log.Infof(ctx, "issue creation disabled")
	}

	s.indexTemplate, err = parseTemplate(staticPath, template.TrustedSourceFromConstant("index.tmpl"))
	if err != nil {
		return nil, err
	}
	s.handle(ctx, "/", s.indexPage)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticPath.String()))))
	s.handle(ctx, "/favicon.ico", func(w http.ResponseWriter, r *http.Request) error {
		http.ServeFile(w, r, filepath.Join(staticPath.String(), "favicon.ico"))
		return nil
	})

	// update: Update the DB from the cvelist repo head and decide which CVEs need issues.
	s.handle(ctx, "/update", s.handleUpdate)
	// issues: File issues on GitHub for CVEs that need them.
	s.handle(ctx, "/issues", s.handleIssues)
	// update-and-issues: do update followed by issues.
	s.handle(ctx, "/update-and-issues", s.handleUpdateAndIssues)
	// scan-repos: scan various modules for vulnerabilities
	s.handle(ctx, "/scan-modules", s.handleScanModules)
	return s, nil
}

func (s *Server) handle(_ context.Context, pattern string, handler func(w http.ResponseWriter, r *http.Request) error) {
	http.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		r = s.beforeRequest(r)
		defer s.afterRequest()
		ctx := r.Context()
		log.With("httpRequest", r).Infof(ctx, "starting %s", r.URL.Path)

		w2 := &responseWriter{ResponseWriter: w}
		if err := handler(w2, r); err != nil {
			s.serveError(ctx, w2, r, err)
		}
		log.With(
			"latency", time.Since(start),
			"status", translateStatus(w2.status)).
			Infof(ctx, "request end")
	})
}

func (s *Server) beforeRequest(r *http.Request) *http.Request {
	traceID := r.Header.Get("X-Cloud-Trace-Context")
	exporter := event.NewExporter(multiEventHandler{
		log.NewGCPJSONHandler(os.Stderr, traceID),
		s.traceHandler,
		s.metricHandler,
	}, nil)
	ctx := event.WithExporter(r.Context(), exporter)
	ctx = s.propagator.Extract(ctx, propagation.HeaderCarrier(r.Header))
	return r.WithContext(ctx)
}

type serverError struct {
	status int   // HTTP status code
	err    error // wrapped error
}

func (s *serverError) Error() string {
	return fmt.Sprintf("%d (%s): %v", s.status, http.StatusText(s.status), s.err)
}

func (s *Server) serveError(ctx context.Context, w http.ResponseWriter, _ *http.Request, err error) {
	serr, ok := err.(*serverError)
	if !ok {
		serr = &serverError{status: http.StatusInternalServerError, err: err}
	}
	if serr.status == http.StatusInternalServerError {
		log.Errorf(ctx, serr.err.Error())
	} else {
		log.Warningf(ctx, "returning %d (%s) for error %v", serr.status, http.StatusText(serr.status), err)
	}
	http.Error(w, serr.err.Error(), serr.status)
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func translateStatus(code int) int64 {
	if code == 0 {
		return http.StatusOK
	}
	return int64(code)
}

// Parse a template.
func parseTemplate(staticPath, filename template.TrustedSource) (*template.Template, error) {
	if staticPath.String() == "" {
		return nil, nil
	}
	templatePath := template.TrustedSourceJoin(staticPath, filename)
	return template.New(filename.String()).Funcs(template.FuncMap{
		"timefmt":  FormatTime,
		"commasep": func(s []string) string { return strings.Join(s, ", ") },
	}).ParseFilesFromTrustedSources(templatePath)
}

var locNewYork *time.Location

func init() {
	var err error
	locNewYork, err = time.LoadLocation("America/New_York")
	if err != nil {
		log.Errorf(context.Background(), "time.LoadLocation: %v", err)
		os.Exit(1)
	}
}

func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(locNewYork).Format("2006-01-02 15:04:05")
}

func renderPage(ctx context.Context, w http.ResponseWriter, page interface{}, tmpl *template.Template) (err error) {
	defer derrors.Wrap(&err, "renderPage")

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, page); err != nil {
		return err
	}
	if _, err := io.Copy(w, &buf); err != nil {
		log.Errorf(ctx, "copying buffer to ResponseWriter: %v", err)
		return err
	}
	return nil
}

type indexPage struct {
	CVEListRepoURL   string
	Namespace        string
	Updates          []*store.CommitUpdateRecord
	CVEsNeedingIssue []*store.CVERecord
	CVEsUpdatedSince []*store.CVERecord
	ModuleScans      []*store.ModuleScanRecord
}

func (s *Server) indexPage(w http.ResponseWriter, r *http.Request) error {

	var page = indexPage{
		CVEListRepoURL: cvelistrepo.URL,
		Namespace:      s.cfg.Namespace,
	}

	g, ctx := errgroup.WithContext(r.Context())
	g.Go(func() error {
		var err error
		page.Updates, err = s.cfg.Store.ListCommitUpdateRecords(ctx, 10)
		return err
	})
	g.Go(func() error {
		var err error
		page.CVEsNeedingIssue, err = s.cfg.Store.ListCVERecordsWithTriageState(ctx, store.TriageStateNeedsIssue)
		return err
	})
	g.Go(func() error {
		var err error
		page.CVEsUpdatedSince, err = s.cfg.Store.ListCVERecordsWithTriageState(ctx, store.TriageStateUpdatedSinceIssueCreation)
		return err
	})
	g.Go(func() error {
		var err error
		page.ModuleScans, err = s.cfg.Store.ListModuleScanRecords(ctx, 300)
		return err
	})
	if err := g.Wait(); err != nil {
		return err
	}
	return renderPage(r.Context(), w, page, s.indexTemplate)
}

const metricNamespace = "vulndb/worker"

var updateCounter = event.NewCounter("updates", &event.MetricOptions{Namespace: metricNamespace})

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) error {
	err := s.doUpdate(r)
	if err == nil {
		fmt.Fprintf(w, "Update succeeded.\n")
	}
	return err
}

func (s *Server) doUpdate(r *http.Request) (err error) {
	defer func() {
		updateCounter.Record(r.Context(), 1, event.Bool("success", err == nil))
		log.Debugf(r.Context(), "recorded one update")
	}()

	if r.Method != http.MethodPost {
		return &serverError{
			status: http.StatusMethodNotAllowed,
			err:    fmt.Errorf("%s required", http.MethodPost),
		}
	}
	force := false
	if f := r.FormValue("force"); f == "true" {
		force = true
	}
	err = UpdateCVEsAtCommit(r.Context(), cvelistrepo.URL, "HEAD", s.cfg.Store, pkgsiteURL, force)
	if cerr := new(CheckUpdateError); errors.As(err, &cerr) {
		return &serverError{
			status: http.StatusPreconditionFailed,
			err:    fmt.Errorf("%w; use /update?force=true to override", cerr),
		}
	}
	if err != nil {
		return err
	}
	listSAs := func(ctx context.Context, since time.Time) ([]*ghsa.SecurityAdvisory, error) {
		const withoutCVES = false
		return ghsa.List(ctx, s.cfg.GitHubAccessToken, since, withoutCVES)
	}
	_, err = UpdateGHSAs(r.Context(), listSAs, s.cfg.Store)
	return err

}

func (s *Server) handleIssues(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return &serverError{
			status: http.StatusMethodNotAllowed,
			err:    fmt.Errorf("%s required", http.MethodPost),
		}
	}
	if s.issueClient == nil {
		return &serverError{
			status: http.StatusPreconditionFailed,
			err:    errors.New("issue creation disabled"),
		}
	}
	// Unless explicitly asked to, don't create more than a few issues.
	limit := 10
	if sl := r.FormValue("limit"); sl != "" {
		var err error
		limit, err = strconv.Atoi(sl)
		if err != nil {
			return &serverError{
				status: http.StatusBadRequest,
				err:    fmt.Errorf("parsing limit query param: %w", err),
			}
		}
	}
	log.With("limit", limit).Infof(r.Context(), "creating issues")
	return CreateIssues(r.Context(), s.cfg.Store, s.issueClient, limit)
}

var updateAndIssuesInProgress atomic.Value

func init() {
	updateAndIssuesInProgress.Store(false)
}

func (s *Server) handleUpdateAndIssues(w http.ResponseWriter, r *http.Request) error {
	if updateAndIssuesInProgress.Load().(bool) {
		return &serverError{
			status: http.StatusPreconditionFailed,
			err:    errors.New("update-and-issues already in progress"),
		}
	}
	updateAndIssuesInProgress.Store(true)
	defer func() { updateAndIssuesInProgress.Store(false) }()

	if err := s.doUpdate(r); err != nil {
		return err
	}
	return s.handleIssues(w, r)
}

func (s *Server) handleScanModules(w http.ResponseWriter, r *http.Request) error {
	return ScanModules(r.Context(), s.cfg.Store)
}

func initOpenTelemetry(projectID string) (tp *sdktrace.TracerProvider, mp metric.MeterProvider, err error) {
	defer derrors.Wrap(&err, "initOpenTelemetry(%q)", projectID)

	exporter, err := texporter.New(texporter.WithProjectID(projectID))
	if err != nil {
		return nil, nil, err
	}
	tp = sdktrace.NewTracerProvider(
		// Enable tracing if there is no incoming request, or if the incoming
		// request is sampled.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithBatcher(exporter))

	// Create exporter (collector embedded with the exporter).
	controller, err := mexporter.NewExportPipeline([]mexporter.Option{mexporter.WithProjectID(projectID)})
	if err != nil {
		return nil, nil, err
	}
	return tp, controller, nil
}

// multiEventHandler is an event.Handler that calls all of its contained handlers
// on each event.
type multiEventHandler []event.Handler

// Event implements event.Handler.Event.
func (eh multiEventHandler) Event(ctx context.Context, ev *event.Event) context.Context {
	for _, h := range eh {
		ctx = h.Event(ctx, ev)
	}
	return ctx
}
