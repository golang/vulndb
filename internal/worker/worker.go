// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

// This file has the public API of the worker, used by cmd/worker as well
// as the server in this package.

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/cveutils"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/observe"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

// UpdateCVEsAtCommit performs an update on the store using the given commit.
// Unless force is true, it checks that the update makes sense before doing it.
func UpdateCVEsAtCommit(ctx context.Context, repoPath, commitHashString string, st store.Store, pc *pkgsite.Client, rc *report.Client, force bool) (err error) {
	defer derrors.Wrap(&err, "RunCommitUpdate(%q, %q, force=%t)", repoPath, commitHashString, force)

	log.Infof(ctx, "updating false positives")
	if err := updateFalsePositives(ctx, st); err != nil {
		return err
	}

	repo, err := gitrepo.CloneOrOpen(ctx, repoPath)
	if err != nil {
		return err
	}
	var commitHash plumbing.Hash
	if commitHashString == "HEAD" {
		ref, err := repo.Reference(plumbing.HEAD, true)
		if err != nil {
			return err
		}
		commitHash = ref.Hash()
	} else {
		commitHash = plumbing.NewHash(commitHashString)
	}
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return err
	}
	if !force {
		if err := checkCVEUpdate(ctx, commit, st); err != nil {
			return err
		}
	}
	u := newCVEUpdater(repo, commit, st, rc, func(cve *cve4.CVE) (*cveutils.TriageResult, error) {
		return cveutils.TriageCVE(ctx, cve, pc)
	})
	return u.update(ctx)
}

// checkCVEUpdate performs sanity checks on a potential update.
// It verifies that there is not an update currently in progress,
// and it makes sure that the update is to a more recent commit.
func checkCVEUpdate(ctx context.Context, commit *object.Commit, st store.Store) error {
	ctx, span := observe.Start(ctx, "checkUpdate")
	defer span.End()

	urs, err := st.ListCommitUpdateRecords(ctx, 1)
	if err != nil {
		return err
	}
	if len(urs) == 0 {
		// No updates, we're good.
		return nil
	}
	// If the most recent update started recently but didn't finish, don't proceed to avoid
	// concurrent updates.
	lu := urs[0]
	if lu.EndedAt.IsZero() && time.Since(lu.StartedAt) < 2*time.Hour {
		return &CheckUpdateError{
			msg: fmt.Sprintf("latest update started %s ago and has not finished", time.Since(lu.StartedAt)),
		}
	}
	if commit.Committer.When.Before(lu.CommitTime) {
		return &CheckUpdateError{
			msg: fmt.Sprintf("commit %s time %s is before latest update commit %s time %s",
				commit.Hash, commit.Committer.When.Format(time.RFC3339),
				lu.CommitHash, lu.CommitTime.Format(time.RFC3339)),
		}
	}
	return nil
}

// CheckUpdateError is an error returned from UpdateCommit that can be avoided
// calling UpdateCommit with force set to true.
type CheckUpdateError struct {
	msg string
}

func (c *CheckUpdateError) Error() string {
	return c.msg
}

const (
	vulnDBBucket = "go-vulndb"
	vulnDBURL    = "https://storage.googleapis.com/" + vulnDBBucket
)

// GHSAListFunc is the type of a function that lists GitHub security advisories.
type GHSAListFunc func(_ context.Context, since time.Time) ([]*ghsa.SecurityAdvisory, error)

// UpdateGHSAs updates the store with the current state of GitHub's security advisories.
func UpdateGHSAs(ctx context.Context, list GHSAListFunc, st store.Store) (_ UpdateGHSAStats, err error) {
	defer derrors.Wrap(&err, "UpdateGHSAs")

	// Find the most recent update time of the records we have in the store.
	grs, err := getGHSARecords(ctx, st)
	var since time.Time
	for _, gr := range grs {
		if gr.GHSA.UpdatedAt.After(since) {
			since = gr.GHSA.UpdatedAt
		}
	}
	// We want to start just after that time.
	since = since.Add(time.Nanosecond)

	// Do the update.
	return updateGHSAs(ctx, list, since, st)
}

func getGHSARecords(ctx context.Context, st store.Store) ([]*store.GHSARecord, error) {
	var rs []*store.GHSARecord
	err := st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
		var err error
		rs, err = tx.GetGHSARecords()
		return err
	})
	if err != nil {
		return nil, err
	}
	return rs, nil
}

// Limit GitHub issue creation requests to this many per second.
const issueQPS = 1

// The limiter used to throttle pkgsite requests.
// The second argument to rate.NewLimiter is the burst, which
// basically lets you exceed the rate briefly.
var issueRateLimiter = rate.NewLimiter(rate.Every(time.Duration(1000/float64(issueQPS))*time.Millisecond), 1)

// CreateIssues creates issues on the x/vulndb issue tracker for allReports.
func CreateIssues(ctx context.Context, st store.Store, client *issues.Client, pc *proxy.Client, rc *report.Client, limit int) (err error) {
	defer derrors.Wrap(&err, "CreateIssues(destination: %s)", client.Destination())
	ctx, span := observe.Start(ctx, "CreateIssues")
	defer span.End()

	if err := createCVEIssues(ctx, st, client, pc, rc, limit); err != nil {
		return err
	}
	return createGHSAIssues(ctx, st, client, pc, rc, limit)
}

// xref returns cross-references for a report: Information about other reports
// for the same CVE, GHSA, or module.
func xref(r *report.Report, rc *report.Client) string {
	out := &strings.Builder{}
	sorted := func(s []string) []string {
		s = slices.Clone(s)
		slices.Sort(s)
		return s
	}

	matches := rc.XRef(r)
	for _, fname := range sorted(maps.Keys(matches)) {
		for _, match := range sorted(matches[fname]) {
			// Getting issue number from file name
			var appearsIn string
			_, _, issueNum, err := report.ParseFilepath(fname)
			if err != nil {
				appearsIn = fmt.Sprintf("%s (unable to convert file name to issue number, %v)", fname, err)
			} else {
				appearsIn = strconv.Itoa(issueNum)
			}

			fmt.Fprintf(out, "- %v appears in issue #%v", match, appearsIn)
			if r, ok := rc.Report(fname); ok {
				if r.IsExcluded() {
					fmt.Fprintf(out, "  %v", r.Excluded)
				}
			}
			fmt.Fprintf(out, "\n")
		}
	}
	if len(matches) == 0 {
		fmt.Fprint(out, "No existing reports found with this module or alias.")
	}
	return out.String()
}

func createCVEIssues(ctx context.Context, st store.Store, client *issues.Client, pc *proxy.Client, rc *report.Client, limit int) (err error) {
	defer derrors.Wrap(&err, "createCVEIssues(destination: %s)", client.Destination())

	needsIssue, err := st.ListCVERecordsWithTriageState(ctx, store.TriageStateNeedsIssue)
	if err != nil {
		return err
	}
	log.Infof(ctx, "createCVEIssues starting; destination: %s, total needing issue: %d",
		client.Destination(), len(needsIssue))
	numCreated := 0
	for _, cr := range needsIssue {
		if limit > 0 && numCreated >= limit {
			break
		}
		ref, err := createIssue(ctx, cr, client, pc, rc)
		if err != nil {
			return err
		}

		// Update the CVERecord in the DB with issue information.
		err = st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
			rs, err := tx.GetCVERecords(cr.ID, cr.ID)
			if err != nil {
				return err
			}
			cr := rs[0]
			cr.TriageState = store.TriageStateIssueCreated
			cr.IssueReference = ref
			cr.IssueCreatedAt = time.Now()
			return tx.SetCVERecord(cr)
		})
		if err != nil {
			return err
		}
		numCreated++
	}
	log.With("limit", limit).Infof(ctx, "createCVEIssues done: %d created", numCreated)
	return nil
}

func createGHSAIssues(ctx context.Context, st store.Store, client *issues.Client, pc *proxy.Client, rc *report.Client, limit int) (err error) {
	defer derrors.Wrap(&err, "createGHSAIssues(destination: %s)", client.Destination())

	sas, err := getGHSARecords(ctx, st)
	if err != nil {
		return err
	}
	var needsIssue []*store.GHSARecord
	for _, sa := range sas {
		if sa.TriageState == store.TriageStateNeedsIssue {
			needsIssue = append(needsIssue, sa)
		}
	}

	log.Infof(ctx, "createGHSAIssues starting; destination: %s, total needing issue: %d",
		client.Destination(), len(needsIssue))
	numCreated := 0
	for _, gr := range needsIssue {
		if limit > 0 && numCreated >= limit {
			break
		}
		// TODO(https://github.com/golang/go/issues/54049): Move this
		// check to the triage step of the worker.
		if isDuplicate(gr.GHSA, pc, rc) {
			// Update the GHSARecord in the DB to reflect that the GHSA
			// already has an advisory.
			if err = st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
				r, err := tx.GetGHSARecord(gr.GetID())
				if err != nil {
					return err
				}
				r.TriageState = store.TriageStateHasVuln
				return tx.SetGHSARecord(r)
			}); err != nil {
				return err
			}
			// Do not create an issue.
			continue
		}
		ref, err := createIssue(ctx, gr, client, pc, rc)
		if err != nil {
			return err
		}
		// Update the GHSARecord in the DB with issue information.
		err = st.RunTransaction(ctx, func(ctx context.Context, tx store.Transaction) error {
			r, err := tx.GetGHSARecord(gr.GetID())
			if err != nil {
				return err
			}
			r.TriageState = store.TriageStateIssueCreated
			r.IssueReference = ref
			r.IssueCreatedAt = time.Now()
			return tx.SetGHSARecord(r)
		})
		if err != nil {
			return err
		}
		numCreated++
	}
	log.With("limit", limit).Infof(ctx, "createGHSAIssues done: %d created", numCreated)
	return nil
}

func isDuplicate(sa *ghsa.SecurityAdvisory, pc *proxy.Client, rc *report.Client) bool {
	r := report.New(sa, pc)
	for _, aliases := range rc.XRef(r) {
		if slices.Contains(aliases, sa.ID) {
			return true
		}
	}
	return false
}

func NewIssueBody(r *report.Report, rc *report.Client) (body string, err error) {
	// Truncate the description if it is too long.
	desc := string(r.Description)
	if len(desc) > 600 {
		desc = desc[:600] + "..."
	}

	r.Description = ""
	rs, err := r.ToString()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := issueTemplate.Execute(&b, issueTemplateData{
		SourceID:     r.SourceMeta.ID,
		AdvisoryLink: idstr.AdvisoryLink(r.SourceMeta.ID),
		Description:  desc,
		Xrefs:        xref(r, rc),
		Report:       r,
		ReportStr:    rs,
		Pre:          "```",
	}); err != nil {
		return "", err
	}
	return b.String(), nil
}

type storeRecord interface {
	GetID() string
	GetSource() report.Source
	GetUnit() string
	GetIssueReference() string
	GetIssueCreatedAt() time.Time
}

func createIssue(ctx context.Context, r storeRecord, client *issues.Client, pc *proxy.Client, rc *report.Client) (ref string, err error) {
	id := r.GetID()
	defer derrors.Wrap(&err, "createIssue(%s)", id)

	if r.GetIssueReference() != "" || !r.GetIssueCreatedAt().IsZero() {
		log.With(
			"ID", id,
			"IssueReference", r.GetIssueReference(),
			"IssueCreatedAt", r.GetIssueCreatedAt(),
		).Errorf(ctx, "%s: triage state is NeedsIssue but issue field(s) non-zero; skipping", id)
		return "", nil
	}

	src := r.GetSource()
	if src == nil || reflect.ValueOf(src).IsNil() {
		log.With("ID", id).Errorf(ctx, "%s: triage state is NeedsIssue but source record is nil; skipping: %v", id, err)
		return "", nil
	}

	rep := report.New(src, pc,
		report.WithModulePath(r.GetUnit()))
	body, err := NewIssueBody(rep, rc)
	if err != nil {
		log.With("ID", id).Errorf(ctx, "%s: triage state is NeedsIssue but could not generate body; skipping: %v", id, err)
		return "", nil
	}

	labels := []string{"NeedsTriage"}
	yrLabel := yearLabel(r.GetID())
	if yrLabel != "" {
		labels = append(labels, yrLabel)
	}

	// Create the issue.
	iss := &issues.Issue{
		Title:  fmt.Sprintf("x/vulndb: potential Go vuln in %s: %s", r.GetUnit(), r.GetID()),
		Body:   body,
		Labels: labels,
	}
	if err := issueRateLimiter.Wait(ctx); err != nil {
		return "", err
	}
	num, err := client.CreateIssue(ctx, iss)
	if err != nil {
		return "", fmt.Errorf("creating issue for %s: %w", id, err)
	}
	// If we crashed here, we would have filed an issue without recording
	// that fact in the DB. That can lead to duplicate issues, but nothing
	// worse (we won't miss a CVE).
	// TODO(https://go.dev/issue/49733): look for the issue title to avoid duplications.
	ref = client.Reference(num)
	log.With("ID", id).Infof(ctx, "created issue %s for %s", ref, id)
	return ref, nil
}

func yearLabel(cve string) string {
	if !strings.HasPrefix(cve, "CVE-") {
		return ""
	}
	parts := strings.Split(cve, "-")
	if len(parts) != 3 {
		return ""
	}
	year, err := strconv.Atoi(parts[1])
	if err != nil {
		return ""
	}
	if year > 2019 {
		return fmt.Sprintf("cve-year-%s", parts[1])
	}
	return "cve-year-2019-and-earlier"
}

type issueTemplateData struct {
	*report.Report
	SourceID     string
	AdvisoryLink string
	Description  string
	Xrefs        string
	ReportStr    string
	Pre          string // markdown string for a <pre> block
}

var issueTemplate = template.Must(template.New("issue").Parse(`Advisory [{{.SourceID}}]({{.AdvisoryLink}}) references a vulnerability in the following Go modules:

| Module |
| - |{{range .Modules}}
| [{{.Module}}](https://pkg.go.dev/{{.Module}}) |{{end}}

Description:
{{.Description}}

References:{{range .References}}
- {{.Type}}: {{.URL}}{{end}}

Cross references:
{{.Xrefs}}
See [doc/triage.md](https://github.com/golang/vulndb/blob/master/doc/triage.md) for instructions on how to triage this report.

{{if (and .Pre .ReportStr) -}}
{{.Pre}}
{{.ReportStr}}
{{.Pre}}
{{- end}}`))
