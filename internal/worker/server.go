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
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cloud.google.com/go/errorreporting"
	"github.com/google/safehtml/template"
	"github.com/jba/metrics"
	"golang.org/x/sync/errgroup"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/observe"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

const (
	pkgsiteURL = "https://pkg.go.dev"
	serverName = "vulndb-worker"
)

var staticPath = template.TrustedSourceFromConstant("internal/worker/static")

type Server struct {
	cfg           Config
	indexTemplate *template.Template
	issueClient   *issues.Client
	ghsaClient    *ghsa.Client
	proxyClient   *proxy.Client
	reportClient  *report.Client
	observer      *observe.Observer
}

func NewServer(ctx context.Context, cfg Config) (_ *Server, err error) {
	defer derrors.Wrap(&err, "NewServer(%q)", cfg.Namespace)

	s := &Server{cfg: cfg}

	s.observer, err = observe.NewObserver(ctx, cfg.Project, serverName)
	if err != nil {
		return nil, err
	}
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

	s.ghsaClient = ghsa.NewClient(ctx, cfg.GitHubAccessToken)
	if cfg.IssueRepo != "" {
		owner, repoName, err := gitrepo.ParseGitHubRepo(cfg.IssueRepo)
		if err != nil {
			return nil, err
		}
		s.issueClient = issues.NewClient(ctx, &issues.Config{
			Owner: owner,
			Repo:  repoName,
			Token: cfg.GitHubAccessToken,
		})
		log.Infof(ctx, "issue creation enabled for repo %s", cfg.IssueRepo)
	} else {
		log.Infof(ctx, "issue creation disabled")
	}

	s.proxyClient = proxy.NewDefaultClient()

	rc, err := report.NewDefaultClient(ctx)
	if err != nil {
		return nil, err
	}
	s.reportClient = rc

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

	// update: Update the DB from the cvelist repo head and the Github Security
	// Advisories API and decide which CVEs and GHSAs need issues.
	s.handle(ctx, "/update", s.handleUpdate)
	// issues: File issues on GitHub for CVEs and GHSAs that need them.
	s.handle(ctx, "/issues", s.handleIssues)
	// update-and-issues: do update followed by issues.
	s.handle(ctx, "/update-and-issues", s.handleUpdateAndIssues)
	return s, nil
}

func (s *Server) handle(_ context.Context, pattern string, hfunc func(w http.ResponseWriter, r *http.Request) error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()
		log.With("httpRequest", r).Infof(ctx, "starting %s", r.URL.Path)

		w2 := &responseWriter{ResponseWriter: w}
		if err := hfunc(w2, r); err != nil {
			s.serveError(ctx, w2, r, err)
		}
		log.With(
			"latency", time.Since(start),
			"status", translateStatus(w2.status)).
			Infof(ctx, "finished %s", r.URL.Path)
	})
	http.Handle(pattern, s.observer.Observe(handler))
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
		log.Errorf(ctx, "returning %d (%s) for error %v", serr.status, http.StatusText(serr.status), err)
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
	BuildInfo        string
	CVEListRepoURL   string
	Namespace        string
	Updates          []*store.CommitUpdateRecord
	CVEsNeedingIssue []*store.CVE4Record
	CVEsUpdatedSince []*store.CVE4Record
}

func (s *Server) indexPage(w http.ResponseWriter, r *http.Request) error {

	var page = indexPage{
		CVEListRepoURL: cvelistrepo.URLv4,
		Namespace:      s.cfg.Namespace,
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		page.BuildInfo = "(no build information)"
	} else {
		commit := "unknown"
		modified := false
		for _, bs := range buildInfo.Settings {
			switch bs.Key {
			case "vcs.revision":
				commit = bs.Value
			case "vcs.modified":
				modified = (bs.Value == "true")
			}
		}
		page.BuildInfo = fmt.Sprintf("Commit %s", commit)
		if modified {
			page.BuildInfo += " (dirty)"
		}
	}
	g, ctx := errgroup.WithContext(r.Context())
	g.Go(func() error {
		var err error
		page.Updates, err = s.cfg.Store.ListCommitUpdateRecords(ctx, 10)
		return err
	})
	g.Go(func() error {
		var err error
		page.CVEsNeedingIssue, err = s.cfg.Store.ListCVE4RecordsWithTriageState(ctx, store.TriageStateNeedsIssue)
		return err
	})
	g.Go(func() error {
		var err error
		page.CVEsUpdatedSince, err = s.cfg.Store.ListCVE4RecordsWithTriageState(ctx, store.TriageStateUpdatedSinceIssueCreation)
		return err
	})
	if err := g.Wait(); err != nil {
		return err
	}
	return renderPage(r.Context(), w, page, s.indexTemplate)
}

type UpdateOutcome struct {
	Success bool
}

var updateCounters = metrics.NewCounterGroup[int64, UpdateOutcome]("updates", "calls to handleUpdate")

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) error {
	err := s.doUpdate(r)
	if err == nil {
		fmt.Fprintf(w, "Update succeeded.\n")
	}
	return err
}

func (s *Server) doUpdate(r *http.Request) (err error) {
	defer func() {
		success := err == nil
		updateCounters.At(UpdateOutcome{success}).Add(1)
		log.Debugf(r.Context(), "recorded one /update operation in counter (success=%t)", success)
	}()

	if r.Method != http.MethodPost {
		return &serverError{
			status: http.StatusMethodNotAllowed,
			err:    fmt.Errorf("%s required", http.MethodPost),
		}
	}
	force := (r.FormValue("force") == "true")

	rc, err := report.NewDefaultClient(r.Context())
	if err != nil {
		return err
	}

	err = UpdateCVEsAtCommit(r.Context(), cvelistrepo.URLv4, "HEAD", s.cfg.Store, pkgsite.Default(), rc, force)
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
		return s.ghsaClient.List(ctx, since)
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
	return CreateIssues(r.Context(), s.cfg.Store, s.issueClient, s.proxyClient, s.reportClient, limit)
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
