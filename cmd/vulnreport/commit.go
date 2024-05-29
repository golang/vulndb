// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"golang.org/x/exp/maps"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/report"
)

var (
	// Note: It would be probably be ideal if -dry did not stage
	// the files, but the logic to determine the commit message
	// currently depends on the status of the staging area.
	dry   = flag.Bool("dry", false, "for commit & create-excluded, stage but do not commit files")
	batch = flag.Bool("batch", false, "for commit, create a single commit for all reports")
)

type commit struct {
	*committer
	*fixer
	filenameParser

	toCommit []*report.Report
	// only commit reports with this review status
	reviewStatus report.ReviewStatus
}

func (commit) name() string { return "commit" }

func (commit) usage() (string, string) {
	const desc = "creates new commits for YAML reports"
	return filenameArgs, desc
}

func (c *commit) setup(ctx context.Context) error {
	c.committer = new(committer)
	c.fixer = new(fixer)

	rs, ok := report.ToReviewStatus(*reviewStatus)
	if !ok {
		return fmt.Errorf("invalid -status=%s", rs)
	}
	c.reviewStatus = rs

	return setupAll(ctx, c.committer, c.fixer)
}

func (c *commit) parseArgs(ctx context.Context, args []string) (filenames []string, _ error) {
	if len(args) != 0 {
		return c.filenameParser.parseArgs(ctx, args)
	}

	// With no arguments, operate on all the changed/added YAML files.
	statusMap, err := c.gitStatus()
	if err != nil {
		return nil, err
	}

	for fname, status := range statusMap {
		if report.IsYAMLReport(fname) && status.Worktree != git.Deleted {
			filenames = append(filenames, fname)
		}
	}

	if len(filenames) == 0 {
		return nil, fmt.Errorf("no arguments provided, and no added/changed YAML files found")
	}

	return filenames, nil
}

func (c *commit) close() error {
	if len(c.toCommit) > 0 {
		return c.commit(c.toCommit...)
	}
	return nil
}

func (c *commit) run(ctx context.Context, filename string) (err error) {
	r, err := report.ReadStrict(filename)
	if err != nil {
		return err
	}

	// If the -status=<REVIEW_STATUS> flag is specified, skip reports
	// with a different status.
	if c.reviewStatus != 0 && r.ReviewStatus != c.reviewStatus {
		log.Infof("skipping %s which has review status %s", r.ID, r.ReviewStatus)
		return nil
	}

	// Clean up the report file and ensure derived files are up-to-date.
	// Stop if there any problems.
	if err := c.fixAndWriteAll(ctx, r); err != nil {
		return err
	}

	if *batch {
		c.toCommit = append(c.toCommit, r)
		return nil
	}

	return c.commit(r)
}

type committer struct {
	repo *git.Repository
}

func (c *committer) setup(ctx context.Context) error {
	repo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		return err
	}
	c.repo = repo
	return nil
}

func (c *committer) gitStatus() (git.Status, error) {
	w, err := c.repo.Worktree()
	if err != nil {
		return nil, err
	}
	return w.Status()
}

func (c *committer) commit(reports ...*report.Report) error {
	if len(reports) == 0 {
		log.Infof("no files to commit, exiting")
		return nil
	}

	var globs []string
	for _, r := range reports {
		globs = append(globs, fmt.Sprintf("*%s*", r.ID))
	}

	// Stage all the files.
	if err := gitAdd(globs...); err != nil {
		return err
	}

	status, err := c.gitStatus()
	if err != nil {
		return err
	}

	msg, err := newCommitMessage(status, reports)
	if err != nil {
		return err
	}

	if *dry {
		log.Outf("would commit with message:\n\n%s", msg)
		return nil
	}

	// Commit the files, allowing the user to edit the default commit message.
	return gitCommit(msg, globs...)
}

// actionPhrases determines the action phrases to use to describe what is happening
// in the commit, based on the status of the git staging area.
func actionPhrases(status git.Status, r *report.Report) (reportAction, issueAction string, _ error) {
	const (
		updateIssueAction = "Updates"
		fixIssueAction    = "Fixes"

		addReportAction       = "add"
		deleteReportAction    = "delete"
		unexcludeReportAction = "unexclude"
		updateReportAction    = "update"
	)

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
	case git.Added, git.Untracked:
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
	default:
		return "", "", fmt.Errorf("internal error: could not determine actions for %s (stat: %v)", r.ID, stat)
	}
}

func newCommitMessage(status git.Status, reports []*report.Report) (string, error) {
	actions := make(map[string][]*report.Report)
	issueActions := make(map[string][]*report.Report)
	for _, r := range reports {
		reportAction, issueAction, err := actionPhrases(status, r)
		if err != nil {
			return "", err
		}
		actions[reportAction] = append(actions[reportAction], r)
		issueActions[issueAction] = append(issueActions[issueAction], r)
	}

	b := new(strings.Builder)
	var titleSegments, bodySegments, issueSegments []string
	for action, rs := range actions {
		reportDesc := fmt.Sprintf("%d reports", len(rs))
		if len(rs) == 1 {
			reportDesc = rs[0].ID
		}
		titleSegments = append(titleSegments, fmt.Sprintf("%s %s", action, reportDesc))
	}

	folders := make(map[string]bool)
	for issueAction, rs := range issueActions {
		for _, r := range rs {
			f, err := r.YAMLFilename()
			if err != nil {
				return "", err
			}

			folder, _, issueID, err := report.ParseFilepath(f)
			if err != nil {
				return "", err
			}

			folders[folder] = true
			bodySegments = append(bodySegments, f)
			issueSegments = append(issueSegments, fmt.Sprintf("%s golang/vulndb#%d", issueAction, issueID))
		}
	}

	// title
	b.WriteString(fmt.Sprintf("%s: %s\n", strings.Join(maps.Keys(folders), ","), strings.Join(titleSegments, ", ")))

	// body
	b.WriteString(fmt.Sprintf("%s%s\n\n", listItem, strings.Join(bodySegments, listItem)))

	// issues
	b.WriteString(strings.Join(issueSegments, "\n"))

	return b.String(), nil
}

const listItem = "\n  - "
