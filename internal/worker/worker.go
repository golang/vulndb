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
	"text/template"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/time/rate"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/cveutils"
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
	u := newCVEUpdater(repo, commit, st, rc, func(cve *cveschema.CVE) (*cveutils.TriageResult, error) {
		return cveutils.TriageCVE(ctx, cve, pc)
	})
	_, err = u.update(ctx)
	return err
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

	fmt.Fprint(out, "Cross references:\n")
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

func newCVEBody(sr storeRecord, rc *report.Client, pc *proxy.Client) (string, error) {
	cr := sr.(*store.CVERecord)
	var b strings.Builder
	if cr.CVE == nil {
		return "", fmt.Errorf("cannot create body for CVERecord with nil CVE")
	}
	if cr.CVE.Metadata.ID == "" {
		cr.CVE.Metadata.ID = cr.ID
	}
	r := report.New(report.ToCVE4(cr.CVE), pc, report.WithModulePath(cr.Module))
	r.Description = ""
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

	fmt.Fprintf(&intro, `References:
- NIST: https://nvd.nist.gov/vuln/detail/%s
- JSON: %s/tree/%s/%s`, cr.ID, cvelistrepo.URLv4, cr.CommitHash, cr.Path)
	for _, ref := range r.References {
		fmt.Fprintf(&intro, "\n- %v: %v", strings.ToLower(string(ref.Type)), ref.URL)
	}
	fmt.Fprintf(&intro, "\n- Imported by: https://pkg.go.dev/%s?tab=importedby", cr.Module)
	fmt.Fprintf(&intro, "\n\n%s", xref(r, rc))
	if err := issueTemplate.Execute(&b, issueTemplateData{
		Intro:  intro.String(),
		Report: out,
		Pre:    "```",
	}); err != nil {
		return "", err
	}
	return b.String(), nil
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
	r := report.New(report.ToLegacyGHSA(sa), pc)
	for _, aliases := range rc.XRef(r) {
		if slices.Contains(aliases, sa.ID) {
			return true
		}
	}
	return false
}

func CreateGHSABody(sa *ghsa.SecurityAdvisory, rc *report.Client, pc *proxy.Client) (body string, err error) {
	r := report.New(report.ToLegacyGHSA(sa), pc)
	r.Description = ""
	rs, err := r.ToString()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	intro := fmt.Sprintf(
		"In GitHub Security Advisory [%s](%s), there is a vulnerability in the following Go packages or modules:",
		sa.ID, sa.Permalink)
	intro += "\n\n" + vulnTable(sa.Vulns)
	intro += "\n\n" + xref(r, rc)
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

	var body string
	switch v := r.(type) {
	case *store.GHSARecord:
		body, err = CreateGHSABody(v.GHSA, rc, pc)
	case *store.CVERecord:
		body, err = newCVEBody(v, rc, pc)
	default:
		log.With("ID", id).Errorf(ctx, "%s: record has unexpected type %T; skipping: %v", id, v, err)
		return "", nil
	}
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
