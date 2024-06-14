// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/vulndb/internal/issues"
)

// issueParser implements the "parseArgs" function of the command
// interface, and can be used by commands that operate on Github issues.
type issueParser struct {
	ic        issueClient
	toProcess map[string]*issues.Issue
	open      []*issues.Issue
}

const issueStateOpen = "open"

func (*issueParser) inputType() string {
	return "issue"
}

func (ip *issueParser) openIssues(ctx context.Context) ([]*issues.Issue, error) {
	if ip.open == nil {
		open, err := ip.ic.Issues(ctx, issues.IssuesOptions{State: issueStateOpen})
		if err != nil {
			return nil, err
		}
		ip.open = open
	}
	return ip.open, nil
}

func (ip *issueParser) parseArgs(ctx context.Context, args []string) (issNums []string, _ error) {
	if len(args) > 0 {
		return argsToIDs(args)
	}

	// If no arguments are provided, operate on all open issues.
	open, err := ip.openIssues(ctx)
	if err != nil {
		return nil, err
	}

	for _, iss := range open {
		n := strconv.Itoa(iss.Number)
		ip.toProcess[n] = iss
		issNums = append(issNums, n)
	}

	return issNums, nil
}

func (ip *issueParser) setup(ctx context.Context, env environment) error {
	ic, err := env.IssueClient(ctx)
	if err != nil {
		return err
	}
	ip.ic = ic
	ip.toProcess = make(map[string]*issues.Issue)
	return nil
}

func (ip *issueParser) lookup(ctx context.Context, issNum string) (any, error) {
	iss, ok := ip.toProcess[issNum]
	if !ok {
		n, err := strconv.Atoi(issNum)
		if err != nil {
			return nil, err
		}
		iss, err := ip.ic.Issue(ctx, n)
		if err != nil {
			return nil, err
		}
		ip.toProcess[issNum] = iss
		return iss, nil
	}

	return iss, nil
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
