// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

// This file has the public API of the worker, used by cmd/worker as well
// as the server in this package.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

// UpdateCommit performs an update on the store using the given commit.
// Unless force is true, it checks that the update makes sense before doing it.
func UpdateCommit(ctx context.Context, repoPath, commitHash string, st store.Store, pkgsiteURL string, force bool) (err error) {
	defer derrors.Wrap(&err, "RunCommitUpdate(%q, %q, force=%t)", repoPath, commitHash, force)

	b, err := falsePositivesInserted(ctx, st)
	if err != nil {
		return err
	}
	if !b {
		log.Infof(ctx, "inserting false positives")
		if err := InsertFalsePositives(ctx, st); err != nil {
			return err
		}
	}

	repo, err := gitrepo.CloneOrOpen(ctx, repoPath)
	if err != nil {
		return err
	}
	var ch plumbing.Hash
	if commitHash == "HEAD" {
		ref, err := repo.Reference(plumbing.HEAD, true)
		if err != nil {
			return err
		}
		ch = ref.Hash()
	} else {
		ch = plumbing.NewHash(commitHash)
	}
	if !force {
		if err := checkUpdate(ctx, repo, ch, st); err != nil {
			return err
		}
	}
	knownVulnIDs, err := readVulnDB(ctx)
	if err != nil {
		return err
	}
	u := newUpdater(repo, ch, st, knownVulnIDs, func(cve *cveschema.CVE) (*triageResult, error) {
		return TriageCVE(ctx, cve, pkgsiteURL)
	})
	_, err = u.update(ctx)
	return err
}

// checkUpdate performs sanity checks on a potential update.
// It verifies that there is not an update currently in progress,
// and it makes sure that the update is to a more recent commit.
func checkUpdate(ctx context.Context, repo *git.Repository, commitHash plumbing.Hash, st store.Store) error {
	b, err := falsePositivesInserted(ctx, st)
	if err != nil {
		return err
	}
	if !b {
		return errors.New("false positives not inserted")
	}

	urs, err := st.ListCommitUpdateRecords(ctx, 1)
	if err != nil {
		return err
	}
	if len(urs) == 0 {
		// No updates, we're good.
		return nil
	}
	lu := urs[0]
	if lu.EndedAt.IsZero() {
		return &CheckUpdateError{
			msg: fmt.Sprintf("latest update started %s ago and has not finished", time.Since(lu.StartedAt)),
		}
	}
	if lu.Error != "" {
		return &CheckUpdateError{
			msg: fmt.Sprintf("latest update finished with error %q", lu.Error),
		}
	}
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return err
	}
	if commit.Committer.When.Before(lu.CommitTime) {
		return &CheckUpdateError{
			msg: fmt.Sprintf("commit %s time %s is before latest update commit %s time %s",
				commitHash, commit.Committer.When.Format(time.RFC3339),
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

const vulnDBURL = "https://storage.googleapis.com/go-vulndb"

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

// Limit GitHub issue creation requests to this many per second.
const issueQPS = 1

// The limiter used to throttle pkgsite requests.
// The second argument to rate.NewLimiter is the burst, which
// basically lets you exceed the rate briefly.
var issueRateLimiter = rate.NewLimiter(rate.Every(time.Duration(1000/float64(issueQPS))*time.Millisecond), 1)

func CreateIssues(ctx context.Context, st store.Store, ic IssueClient, limit int) (err error) {
	derrors.Wrap(&err, "CreateIssues(destination: %s)", ic.Destination())

	needsIssue, err := st.ListCVERecordsWithTriageState(ctx, store.TriageStateNeedsIssue)
	if err != nil {
		return err
	}
	log.Infof(ctx, "CreateIssues starting; destination: %s, total needing issue: %d",
		ic.Destination(), len(needsIssue))
	numCreated := int64(0)
	for _, cr := range needsIssue {
		if limit > 0 && int(numCreated) >= limit {
			break
		}
		if cr.IssueReference != "" || !cr.IssueCreatedAt.IsZero() {
			log.With(
				"CVE", cr.ID,
				"IssueReference", cr.IssueReference,
				"IssueCreatedAt", cr.IssueCreatedAt,
			).Errorf(ctx, "%s: triage state is NeedsIssue but issue field(s) non-zero; skipping", cr.ID)
			continue
		}
		body, err := newBody(cr)
		if err != nil {
			log.With(
				"CVE", cr.ID,
				"IssueReference", cr.IssueReference,
				"IssueCreatedAt", cr.IssueCreatedAt,
			).Errorf(ctx, "%s: triage state is NeedsIssue but could not generate body; skipping: %v", cr.ID, err)
			continue
		}

		// Create the issue.
		iss := &Issue{
			Title: fmt.Sprintf("x/vulndb: potential Go vuln in %q: %s", cr.Module, cr.ID),
			Body:  body,
		}
		if err := issueRateLimiter.Wait(ctx); err != nil {
			return err
		}
		num, err := ic.CreateIssue(ctx, iss)
		if err != nil {
			return fmt.Errorf("creating issue for %s: %w", cr.ID, err)
		}
		// If we crashed here, we would have filed an issue without recording
		// that fact in the DB. That can lead to duplicate issues, but nothing
		// worse (we won't miss a CVE).
		// TODO(golang/go#49733): look for the issue title to avoid duplications.
		ref := ic.Reference(num)
		log.With("CVE", cr.ID).Infof(ctx, "created issue %s for %s", ref, cr.ID)

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
	log.With("limit", limit).Infof(ctx, "CreateIssues done: %d created", numCreated)
	return nil
}

const englishLang = "eng"

func newBody(cr *store.CVERecord) (string, error) {
	var b strings.Builder
	var desc string
	if cr.CVE != nil {
		for _, d := range cr.CVE.Description.Data {
			if d.Lang == englishLang {
				desc = d.Value
			}
		}
	}
	err := issueTemplate.Execute(&b, issueTemplateData{
		Heading: fmt.Sprintf(
			"In [%s](%s/tree/%s/%s), the reference URL [%s](%s) (and possibly others) refers to something in Go.",
			cr.ID, gitrepo.CVEListRepoURL, cr.CommitHash, cr.Path, cr.Module, cr.Module),
		Description: desc,
		CVERecord:   cr,
		Pre:         "```",
	})
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

type issueTemplateData struct {
	Heading     string
	Description string
	Pre         string // markdown string for a <pre> block
	*store.CVERecord
}

var issueTemplate = template.Must(template.New("issue").Parse(`
{{- .Heading}}

{{.Pre}}
module: {{.Module}}
package:
stdlib:
versions:
  - introduced:
  - fixed:
description: |
  {{.Description}}

cve: {{.ID}}
credit:
symbols:
  -
published:
links:
  commit:
  pr:
  context:
    -
{{.Pre}}
`))
