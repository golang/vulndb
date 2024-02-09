// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/genai"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var dry = flag.Bool("dry", false, "for create-excluded, do not commit files")

type createExcluded struct {
	gc          *ghsa.Client
	ic          *issues.Client
	pc          *proxy.Client
	ac          *genai.GeminiClient
	rc          *report.Client
	allowClosed bool

	isses   map[string]*issues.Issue
	created []string
}

func (createExcluded) name() string { return "create-excluded" }

func (createExcluded) usage() (string, string) {
	const desc = "creates and commits reports for Github issues marked excluded"
	return "", desc
}

func (c *createExcluded) close() error {
	skipped := len(c.isses) - len(c.created)
	if skipped > 0 {
		log.Infof("skipped %d issue(s)\n", skipped)
	}

	if len(c.created) == 0 {
		log.Infof("no files to commit, exiting")
		return nil
	}

	msg, err := excludedCommitMsg(c.created)
	if err != nil {
		return err
	}

	if *dry {
		log.Outf("create-excluded would commit files:\n\n\t%s\n\nwith message:\n\n%s", strings.Join(c.created, "\n\t"), msg)
		return nil
	}

	if err := gitAdd(c.created...); err != nil {
		return err
	}
	return gitCommit(msg, c.created...)
}

func (c *createExcluded) setup(ctx context.Context) error {
	if *githubToken == "" {
		return fmt.Errorf("githubToken must be provided")
	}
	localRepo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		return err
	}
	rc, err := report.NewClient(localRepo)
	if err != nil {
		return err
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return err
	}
	var aiClient *genai.GeminiClient
	if *useAI {
		aiClient, err = genai.NewGeminiClient(ctx)
		if err != nil {
			return err
		}
	}

	c.ic = issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken})
	c.gc = ghsa.NewClient(ctx, *githubToken)
	c.pc = proxy.NewDefaultClient()
	c.rc = rc
	c.allowClosed = *closedOk
	c.ac = aiClient
	c.isses = make(map[string]*issues.Issue)

	return nil
}

func (c *createExcluded) parseArgs(ctx context.Context, args []string) (issNums []string, err error) {
	if len(args) > 0 {
		return nil, fmt.Errorf("expected no arguments")
	}

	stateOption := "open"
	if c.allowClosed {
		stateOption = "all"
	}

	for _, er := range report.ExcludedReasons {
		label := er.ToLabel()
		is, err := c.ic.Issues(ctx, issues.IssuesOptions{Labels: []string{label}, State: stateOption})
		if err != nil {
			return nil, err
		}
		log.Infof("found %d issues with label %s\n", len(is), label)

		for _, iss := range is {
			if c.rc.HasReport(iss.Number) {
				log.Infof("skipping issue %d which already has a report\n", iss.Number)
				continue
			}

			n := strconv.Itoa(iss.Number)
			c.isses[n] = iss
			issNums = append(issNums, n)
		}
	}

	return issNums, nil
}

func (c *createExcluded) run(ctx context.Context, issNum string) (err error) {
	iss, ok := c.isses[issNum]
	if !ok {
		return fmt.Errorf("BUG: could not find issue %s (this should have been populated in parseArgs)", issNum)
	}

	r, err := createReport(ctx, iss, c.pc, c.gc, c.ac, c.allowClosed)
	if err != nil {
		return err
	}

	filename, err := writeReport(r)
	if err != nil {
		return err
	}

	c.created = append(c.created, filename)
	return nil
}

func excludedCommitMsg(fs []string) (string, error) {
	var issNums []string
	for _, f := range fs {
		_, _, iss, err := report.ParseFilepath(f)
		if err != nil {
			return "", err
		}
		issNums = append(issNums, fmt.Sprintf("Fixes golang/vulndb#%d", iss))
	}

	return fmt.Sprintf(
		`%s: batch add %d excluded reports

Adds excluded reports:
	- %s

%s`,
		report.ExcludedDir,
		len(fs),
		strings.Join(fs, "\n\t- "),
		strings.Join(issNums, "\n")), nil
}
