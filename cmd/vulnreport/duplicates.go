// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

type duplicates struct {
	gc         *ghsa.Client
	ic         *issues.Client
	pc         *proxy.Client
	rc         *report.Client
	trackerURL string

	isses map[string]*issues.Issue

	// protects aliasesToIssues
	mu              sync.Mutex
	aliasesToIssues map[string][]int
}

func (*duplicates) name() string { return "duplicates" }

func (*duplicates) usage() (string, string) {
	const desc = "finds likely duplicates of the given Github issue (with no args, looks at all open issues)"
	return "<no args> | " + ghIssueArgs, desc
}

func (*duplicates) close() error {
	return nil
}

func (c *duplicates) setup(ctx context.Context) error {
	if *githubToken == "" {
		return fmt.Errorf("githubToken must be provided")
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return err
	}

	c.trackerURL = fmt.Sprintf("https://github.com/%s/%s/issues", owner, repoName)
	c.ic = issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken})
	c.gc = ghsa.NewClient(ctx, *githubToken)
	c.pc = proxy.NewDefaultClient()
	c.isses = make(map[string]*issues.Issue)

	localRepo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		return err
	}
	rc, err := report.NewClient(localRepo)
	if err != nil {
		return err
	}
	c.rc = rc

	c.aliasesToIssues = make(map[string][]int)

	return nil
}

func (d *duplicates) parseArgs(ctx context.Context, args []string) (issNums []string, err error) {
	if len(args) > 0 {
		return argsToIDs(args)
	}

	// If no arguments are provided, operate on all open issues.
	is, err := d.ic.Issues(ctx, issues.IssuesOptions{State: "open"})
	if err != nil {
		return nil, err
	}
	log.Infof("found %d open issues", len(is))

	for _, iss := range is {
		n := strconv.Itoa(iss.Number)
		d.isses[n] = iss
		issNums = append(issNums, n)
	}

	return issNums, nil
}

func (d *duplicates) run(ctx context.Context, issNum string) (err error) {
	iss, ok := d.isses[issNum]
	if !ok {
		n, err := strconv.Atoi(issNum)
		if err != nil {
			return err
		}
		iss, err = d.ic.Issue(ctx, n)
		if err != nil {
			return err
		}
	}

	if iss.HasLabel(labelDuplicate) {
		log.Infof("issue #%d is already marked duplicate, skipping", iss.Number)
		return
	}

	parsed, err := parseGithubIssue(iss, d.pc)
	if err != nil {
		return err
	}

	if len(parsed.aliases) == 0 {
		log.Infof("no aliases found for issue #%d (%q), skipping", iss.Number, iss.Title)
		return
	}

	aliases := allAliases(ctx, parsed.aliases, d.gc)
	var allXrefs []string
	for _, a := range aliases {
		var xrefs []string

		// Find existing reports with this alias.
		if reports := d.rc.ReportsByAlias(a); len(reports) != 0 {
			for _, r := range reports {
				fname, err := r.YAMLFilename()
				if err != nil {
					fname = r.ID
				}
				// Skip the report if it corresponds to the issue number.
				// (This happens when there is an unsubmitted report for the issue).
				_, _, in, _ := report.ParseFilepath(fname)
				if in == iss.Number {
					continue
				}
				xrefs = append(xrefs, fname)
			}
		}

		// Find other open issues with this alias.
		if issNums, ok := d.aliasesToIssues[a]; ok {
			for _, in := range issNums {
				xrefs = append(xrefs, d.githubURL(in))
			}
		}

		d.addAlias(a, iss.Number)

		if len(xrefs) != 0 {
			allXrefs = append(allXrefs, fmt.Sprintf("#%d shares alias %s with %s", iss.Number, a, strings.Join(xrefs, ", ")))
		}
	}

	if len(allXrefs) != 0 {
		log.Outf("%s is a likely duplicate:\n - %s", d.githubURL(iss.Number), strings.Join(allXrefs, "\n - "))
	} else {
		log.Infof("found no existing reports or open issues with aliases in issue #%d", iss.Number)
	}
	return nil
}

func (d *duplicates) githubURL(n int) string {
	return fmt.Sprintf("%s/%d", d.trackerURL, n)
}

func (d *duplicates) addAlias(a string, n int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.aliasesToIssues[a] = append(d.aliasesToIssues[a], n)
}
