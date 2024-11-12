// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"golang.org/x/exp/maps"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/report"
)

var (
	// Note: It would be probably be ideal if -dry did not stage
	// the files, but the logic to determine the commit message
	// currently depends on the status of the staging area.
	dry   = flag.Bool("dry", false, "for commit & create-excluded, stage but do not commit files")
	batch = flag.Int("batch", 0, "for commit, create batched commits of the specified size")
)

type commit struct {
	*committer
	*fixer
	*filenameParser

	toCommit []*yamlReport
	// only commit reports with this review status
	reviewStatus report.ReviewStatus
}

func (commit) name() string { return "commit" }

func (commit) usage() (string, string) {
	const desc = "creates new commits for YAML reports"
	return filenameArgs, desc
}

func (c *commit) setup(ctx context.Context, env environment) error {
	c.committer = new(committer)
	c.fixer = new(fixer)
	c.filenameParser = new(filenameParser)

	rs, ok := report.ToReviewStatus(*reviewStatus)
	if !ok {
		return fmt.Errorf("invalid -status=%s", rs)
	}
	c.reviewStatus = rs

	return setupAll(ctx, env, c.committer, c.fixer, c.filenameParser)
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

func (c *commit) close() (err error) {
	if len(c.toCommit) != 0 {
		batchSize := *batch
		slices.SortFunc(c.toCommit, func(a, b *yamlReport) int {
			return cmp.Compare(a.ID, b.ID)
		})
		for start := 0; start < len(c.toCommit); start += batchSize {
			end := min(start+batchSize, len(c.toCommit))
			log.Infof("committing batch %s-%s", c.toCommit[start].ID, c.toCommit[end-1].ID)
			if cerr := c.commit(c.toCommit[start:end]...); err != nil {
				err = errors.Join(err, cerr)
			}
		}
	}
	return err
}

func (c *commit) skip(input any) string {
	r := input.(*yamlReport)

	if c.reviewStatus == 0 {
		return ""
	}

	// If the -status=<REVIEW_STATUS> flag is specified, skip reports
	// with a different status.
	if r.ReviewStatus != c.reviewStatus {
		return fmt.Sprintf("review status is %s", r.ReviewStatus)
	}

	return ""
}

func (c *commit) run(ctx context.Context, input any) error {
	r := input.(*yamlReport)

	// Clean up the report file and ensure derived files are up-to-date.
	// Stop if there any problems.
	if err := c.fixAndWriteAll(ctx, r, false); err != nil {
		return err
	}

	if *batch > 0 {
		c.toCommit = append(c.toCommit, r)
		return nil
	}

	return c.commit(r)
}

type committer struct {
	repo *git.Repository
}

func (c *committer) setup(ctx context.Context, env environment) error {
	repo, err := env.ReportRepo(ctx)
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

func (c *committer) commit(reports ...*yamlReport) error {
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
func actionPhrases(status git.Status, r *yamlReport) (reportAction, issueAction string, _ error) {
	const (
		updateIssueAction = "Updates"
		fixIssueAction    = "Fixes"

		addReportAction       = "add"
		deleteReportAction    = "delete"
		unexcludeReportAction = "unexclude"
		updateReportAction    = "update"
	)

	stat := status.File(r.Filename).Staging
	switch stat {
	case git.Deleted:
		if r.IsExcluded() {
			// It's theoretically OK to just delete an excluded report,
			// because they aren't published anywhere.
			return deleteReportAction, updateIssueAction, nil
		}
		// It's not OK to delete a regular report. These can be withdrawn but not deleted.
		return "", "", fmt.Errorf("cannot delete regular report %s (use withdrawn field instead)", r.Filename)
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
		case r.NeedsReview():
			// Update instead of fixing the issue because we still need
			// to review the report later.
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

func newCommitMessage(status git.Status, reports []*yamlReport) (string, error) {
	actions := make(map[string][]*yamlReport)
	issueActions := make(map[string][]*yamlReport)
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
			folder, _, issueID, err := report.ParseFilepath(r.Filename)
			if err != nil {
				return "", err
			}

			folders[folder] = true
			bodySegments = append(bodySegments, r.Filename)
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
