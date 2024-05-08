// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
)

// issueParser implements the "parseArgs" function of the command
// interface, and can be used by commands that operate on Github issues.
type issueParser struct {
	ic      *issues.Client
	isses   map[string]*issues.Issue
	skipped []string
}

const issueStateOpen = "open"

func (ip *issueParser) parseArgs(ctx context.Context, args []string) (issNums []string, _ error) {
	if len(args) > 0 {
		return argsToIDs(args)
	}

	// If no arguments are provided, operate on all open issues.
	is, err := ip.ic.Issues(ctx, issues.IssuesOptions{State: issueStateOpen})
	if err != nil {
		return nil, err
	}
	log.Infof("no arguments provided - operating on %d open issues", len(is))

	for _, iss := range is {
		n := strconv.Itoa(iss.Number)
		ip.isses[n] = iss
		issNums = append(issNums, n)
	}

	return issNums, nil
}

func (ip *issueParser) setup(ctx context.Context) error {
	if *githubToken == "" {
		return fmt.Errorf("githubToken must be provided")
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return err
	}
	ip.ic = issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken})
	ip.isses = make(map[string]*issues.Issue)
	return nil
}

func (ip *issueParser) lookup(ctx context.Context, issNum string) (*issues.Issue, error) {
	iss, ok := ip.isses[issNum]
	if !ok {
		n, err := strconv.Atoi(issNum)
		if err != nil {
			return nil, err
		}
		iss, err := ip.ic.Issue(ctx, n)
		if err != nil {
			return nil, err
		}
		ip.isses[issNum] = iss
		return iss, nil
	}

	return iss, nil
}

func (ip *issueParser) skip(iss *issues.Issue, skipReason func(*issues.Issue) string) bool {
	if reason := skipReason(iss); reason != "" {
		log.Infof("skipping issue #%d (%s)", iss.Number, reason)
		ip.skipped = append(ip.skipped, fmt.Sprint(iss.Number))
		return true
	}
	return false
}

func (ip *issueParser) close() error {
	if len(ip.skipped) > 0 {
		log.Infof("processed %d issue(s); skipped %d issue(s)", len(ip.isses), len(ip.skipped))
	}
	return nil
}

func argsToIDs(args []string) ([]string, error) {
	var githubIDs []string
	parseGithubID := func(s string) (int, error) {
		id, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("invalid GitHub issue ID: %q", s)
		}
		return id, nil
	}
	for _, arg := range args {
		if !strings.Contains(arg, "-") {
			_, err := parseGithubID(arg)
			if err != nil {
				return nil, err
			}
			githubIDs = append(githubIDs, arg)
			continue
		}
		from, to, _ := strings.Cut(arg, "-")
		fromID, err := parseGithubID(from)
		if err != nil {
			return nil, err
		}
		toID, err := parseGithubID(to)
		if err != nil {
			return nil, err
		}
		if fromID > toID {
			return nil, fmt.Errorf("%v > %v", fromID, toID)
		}
		for id := fromID; id <= toID; id++ {
			githubIDs = append(githubIDs, strconv.Itoa(id))
		}
	}
	return githubIDs, nil
}
