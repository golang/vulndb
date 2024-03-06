// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

type commit struct {
	pc   *proxy.Client
	gc   *ghsa.Client
	repo *git.Repository

	filenameParser
}

func (commit) name() string { return "commit" }

func (commit) usage() (string, string) {
	const desc = "creates new commits for YAML reports"
	return filenameArgs, desc
}

func (c *commit) setup(ctx context.Context) error {
	c.pc = proxy.NewDefaultClient()
	c.gc = ghsa.NewClient(ctx, *githubToken)

	repo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		return err
	}
	c.repo = repo
	return nil
}

func (c *commit) close() error { return nil }

func (c *commit) run(ctx context.Context, filename string) (err error) {
	// Clean up the report file and lint the result.
	// Stop if there any problems.
	r, err := report.ReadAndLint(filename, c.pc)
	if err != nil {
		return err
	}
	if err := fixReport(ctx, r, filename, c.pc, c.gc); err != nil {
		return err
	}
	if hasUnaddressedTodos(r) {
		// Check after fix() as it can add new TODOs.
		return fmt.Errorf("file %q has unaddressed %q fields", filename, "TODO:")
	}

	// Stage all the files related to this report.
	glob := fmt.Sprintf("*%s*", r.ID)
	if err := gitAdd(glob); err != nil {
		return err
	}

	reportAction, issueAction, err := actionPhrases(c.repo, r)
	if err != nil {
		return err
	}

	msg, err := newCommitMsg(r, reportAction, issueAction)
	if err != nil {
		return err
	}

	// Commit the files, allowing the user to edit the default commit message.
	return gitCommit(msg, glob)
}

// actionPhrases determines the action phrases to use to describe what is happening
// in the commit, based on the status of the git staging area.
func actionPhrases(repo *git.Repository, r *report.Report) (reportAction, issueAction string, _ error) {
	const (
		updateIssueAction = "Updates"
		fixIssueAction    = "Fixes"

		addReportAction       = "add"
		deleteReportAction    = "delete"
		unexcludeReportAction = "unexclude"
		updateReportAction    = "update"
	)

	w, err := repo.Worktree()
	if err != nil {
		return "", "", err
	}

	status, err := w.Status()
	if err != nil {
		return "", "", err
	}

	fname, err := r.YAMLFilename()
	if err != nil {
		return "", "", err
	}
	stat := status.File(fname).Staging
	switch stat {
	case git.Deleted:
		if r.IsExcluded() {
			// It's theoretically OK to just delete an excluded report,
			// because they aren't published anywhere.
			return deleteReportAction, updateIssueAction, nil
		}
		// It's not OK to delete a regular report. These can be withdrawn but not deleted.
		return "", "", fmt.Errorf("cannot delete regular report %s (use withdrawn field instead)", fname)
	case git.Added:
		switch {
		case status.File(filepath.Join(report.ExcludedDir, r.ID+".yaml")).Staging == git.Deleted:
			// If a corresponding excluded report is being deleted,
			// this is an unexclude action.
			return unexcludeReportAction, updateIssueAction, nil
		case r.CVEMetadata != nil:
			// Update instead of fixing the issue because we still need
			// to manually publish the CVE record after submitting the CL.
			return addReportAction, updateIssueAction, nil
		default:
			return addReportAction, fixIssueAction, nil
		}
	case git.Modified:
		return updateReportAction, updateIssueAction, nil
	}

	return "", "", fmt.Errorf("internal error: could not determine actions for %s", r.ID)
}

func newCommitMsg(r *report.Report, reportAction, issueAction string) (string, error) {
	f, err := r.YAMLFilename()
	if err != nil {
		return "", err
	}

	folder, filename, issueID, err := report.ParseFilepath(f)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"%s: %s %s\n\nAliases: %s\n\n%s golang/vulndb#%d",
		folder, reportAction, filename, strings.Join(r.Aliases(), ", "),
		issueAction, issueID), nil
}

// hasUnaddressedTodos returns true if report has any unaddressed todos in the
// report, i.e. starts with "TODO:".
func hasUnaddressedTodos(r *report.Report) bool {
	is := func(s string) bool { return strings.HasPrefix(s, "TODO:") }
	any := func(ss []string) bool { return slices.IndexFunc(ss, is) >= 0 }

	if is(string(r.Excluded)) {
		return true
	}
	for _, m := range r.Modules {
		if is(m.Module) {
			return true
		}
		for _, v := range m.Versions {
			if is(string(v.Introduced)) {
				return true
			}
			if is(string(v.Fixed)) {
				return true
			}
		}
		if is(string(m.VulnerableAt)) {
			return true
		}
		for _, p := range m.Packages {
			if is(p.Package) || is(p.SkipFix) || any(p.Symbols) || any(p.DerivedSymbols) {
				return true
			}
		}
	}
	for _, ref := range r.References {
		if is(ref.URL) {
			return true
		}
	}
	if any(r.CVEs) || any(r.GHSAs) {
		return true
	}
	return is(r.Summary.String()) || is(r.Description.String()) || any(r.Credits)
}
