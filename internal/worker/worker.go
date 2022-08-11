// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

// This file has the public API of the worker, used by cmd/worker as well
// as the server in this package.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/exp/event"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

// UpdateCVEsAtCommit performs an update on the store using the given commit.
// Unless force is true, it checks that the update makes sense before doing it.
func UpdateCVEsAtCommit(ctx context.Context, repoPath, commitHashString string, st store.Store, pkgsiteURL string, force bool) (err error) {
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
	knownVulnIDs, err := readVulnDB(ctx)
	if err != nil {
		return err
	}
	u := newCVEUpdater(repo, commit, st, knownVulnIDs, func(cve *cveschema.CVE) (*triageResult, error) {
		return TriageCVE(ctx, cve, pkgsiteURL)
	})
	_, err = u.update(ctx)
	return err
}

// checkCVEUpdate performs sanity checks on a potential update.
// It verifies that there is not an update currently in progress,
// and it makes sure that the update is to a more recent commit.
func checkCVEUpdate(ctx context.Context, commit *object.Commit, st store.Store) error {
	ctx = event.Start(ctx, "checkUpdate")
	defer event.End(ctx)

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
	if lu.Error != "" {
		return &CheckUpdateError{
			msg: fmt.Sprintf("latest update finished with error %q", lu.Error),
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

// readVulnDB returns a list of all CVE IDs in the Go vuln DB.
func readVulnDB(ctx context.Context) ([]string, error) {
	const concurrency = 4

	client, err := vulnc.NewClient([]string{vulnDBURL}, vulnc.Options{})
	if err != nil {
		return nil, err
	}

	goIDs, err := client.ListIDs(ctx)
	if err != nil {
		return nil, err
	}
	var (
		mu     sync.Mutex
		cveIDs []string
	)
	sem := make(chan struct{}, concurrency)
	g, ctx := errgroup.WithContext(ctx)
	for _, id := range goIDs {
		id := id
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			e, err := client.GetByID(ctx, id)
			if err != nil {
				return err
			}
			// Assume all the aliases are CVE IDs.
			mu.Lock()
			cveIDs = append(cveIDs, e.Aliases...)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return cveIDs, nil
}

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

func CreateIssues(ctx context.Context, st store.Store, ic issues.Client, limit int) (err error) {
	defer derrors.Wrap(&err, "CreateIssues(destination: %s)", ic.Destination())
	ctx = event.Start(ctx, "CreateIssues")
	defer event.End(ctx)

	if err := createCVEIssues(ctx, st, ic, limit); err != nil {
		return err
	}
	return createGHSAIssues(ctx, st, ic, limit)
}

func createCVEIssues(ctx context.Context, st store.Store, ic issues.Client, limit int) (err error) {
	defer derrors.Wrap(&err, "createCVEIssues(destination: %s)", ic.Destination())

	needsIssue, err := st.ListCVERecordsWithTriageState(ctx, store.TriageStateNeedsIssue)
	if err != nil {
		return err
	}
	log.Infof(ctx, "createCVEIssues starting; destination: %s, total needing issue: %d",
		ic.Destination(), len(needsIssue))
	numCreated := 0
	for _, cr := range needsIssue {
		if limit > 0 && numCreated >= limit {
			break
		}
		ref, err := createIssue(ctx, cr, ic, newCVEBody)
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

func newCVEBody(sr storeRecord) (string, error) {
	cr := sr.(*store.CVERecord)
	var b strings.Builder
	if cr.CVE == nil {
		return "", fmt.Errorf("cannot create body for CVERecord with nil CVE")
	}
	if cr.CVE.Metadata.ID == "" {
		cr.CVE.Metadata.ID = cr.ID
	}
	r := report.CVEToReport(cr.CVE, cr.Module)
	out, err := r.ToString()
	if err != nil {
		return "", err
	}

	var intro strings.Builder
	fmt.Fprintf(&intro,
		"%s references [%s](https://%s), which may be a Go module.\n\n",
		cr.ID, cr.Module, cr.Module)

	description := "N/A"
	if len(cr.CVE.Description.Data) > 0 {
		description = cr.CVE.Description.Data[0].Value
	}
	fmt.Fprintf(&intro, "Description:\n%s\n\n", description)

	fmt.Fprintf(&intro, `Links:
- NIST: https://nvd.nist.gov/vuln/detail/%s
- JSON: %s/tree/%s/%s`, cr.ID, cvelistrepo.URL, cr.CommitHash, cr.Path)

	if r.Links.Commit != "" {
		fmt.Fprintf(&intro, "\n- Commit: %s", r.Links.Commit)
	}
	if r.Links.PR != "" {
		fmt.Fprintf(&intro, "\n- PR: %s", r.Links.PR)
	}
	fmt.Fprintf(&intro, "\n- Imported by: https://pkg.go.dev/%s?tab=importedby", cr.Module)
	for _, l := range r.Links.Context {
		fmt.Fprintf(&intro, "\n- %s", l)
	}
	if err := issueTemplate.Execute(&b, issueTemplateData{
		Intro:  intro.String(),
		Report: out,
		Pre:    "```",
	}); err != nil {
		return "", err
	}
	return b.String(), nil
}

func createGHSAIssues(ctx context.Context, st store.Store, ic issues.Client, limit int) (err error) {
	defer derrors.Wrap(&err, "createGHSAIssues(destination: %s)", ic.Destination())

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
		ic.Destination(), len(needsIssue))
	numCreated := 0
	for _, gr := range needsIssue {
		if limit > 0 && numCreated >= limit {
			break
		}
		ref, err := createIssue(ctx, gr, ic, newGHSABody)
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

func newGHSABody(sr storeRecord) (string, error) {
	return CreateGHSABody(sr.(*store.GHSARecord).GHSA)
}

func CreateGHSABody(sa *ghsa.SecurityAdvisory) (body string, err error) {
	r := report.GHSAToReport(sa, "")
	rs, err := r.ToString()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	intro := fmt.Sprintf(
		"In GitHub Security Advisory [%s](%s), there is a vulnerability in the following Go packages or modules:",
		sa.GHSA(), sa.Permalink)
	intro += "\n\n" + vulnTable(sa.Vulns)
	if err := issueTemplate.Execute(&b, issueTemplateData{
		Intro:  intro,
		Report: rs,
		Pre:    "```",
	}); err != nil {
		return "", err
	}
	return b.String(), nil
}

func vulnTable(vs []*ghsa.Vuln) string {
	var b strings.Builder
	fmt.Fprintf(&b, "| Unit | Fixed | Vulnerable Ranges |\n")
	fmt.Fprintf(&b, "| - | - | - |\n")
	for _, v := range vs {
		fmt.Fprintf(&b, "| [%s](https://pkg.go.dev/%[1]s) | %s | %s |",
			v.Package, v.EarliestFixedVersion, v.VulnerableVersionRange)
	}
	return b.String()
}

type storeRecord interface {
	GetID() string
	GetPrettyID() string
	GetUnit() string
	GetIssueReference() string
	GetIssueCreatedAt() time.Time
}

func createIssue(ctx context.Context, r storeRecord, ic issues.Client, newBody func(storeRecord) (string, error)) (ref string, err error) {
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
	body, err := newBody(r)
	if err != nil {
		log.With("ID", id).Errorf(ctx, "%s: triage state is NeedsIssue but could not generate body; skipping: %v", id, err)
		return "", nil
	}
	var labels []string
	label := yearLabel(r.GetPrettyID())
	if label != "" {
		labels = append(labels, label)
	}
	// Create the issue.
	iss := &issues.Issue{
		Title:  fmt.Sprintf("x/vulndb: potential Go vuln in %s: %s", r.GetUnit(), r.GetPrettyID()),
		Body:   body,
		Labels: labels,
	}
	if err := issueRateLimiter.Wait(ctx); err != nil {
		return "", err
	}
	num, err := ic.CreateIssue(ctx, iss)
	if err != nil {
		return "", fmt.Errorf("creating issue for %s: %w", id, err)
	}
	// If we crashed here, we would have filed an issue without recording
	// that fact in the DB. That can lead to duplicate issues, but nothing
	// worse (we won't miss a CVE).
	// TODO(https://go.dev/issue/49733): look for the issue title to avoid duplications.
	ref = ic.Reference(num)
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
	Intro  string
	Report string
	Pre    string // markdown string for a <pre> block
	*store.CVERecord
}

var issueTemplate = template.Must(template.New("issue").Parse(`
{{- .Intro}}

See [doc/triage.md](https://github.com/golang/vulndb/blob/master/doc/triage.md) for instructions on how to triage this report.

{{if (and .Pre .Report) -}}
{{.Pre}}
{{.Report}}
{{.Pre}}
{{- end}}`))
