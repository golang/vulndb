// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"

	"golang.org/x/vulndb/internal/issues"
)

var (
	preferCVE       = flag.Bool("cve", false, "for create, prefer CVEs over GHSAs as canonical source")
	useAI           = flag.Bool("ai", false, "for create, use AI to write draft summary and description when creating report")
	populateSymbols = flag.Bool("symbols", false, "for create, attempt to auto-populate symbols")
	user            = flag.String("user", "", "for create & create-excluded, only consider issues assigned to the given user")
	reviewStatus    = flag.String("status", "", "for create, use this review status (REVIEWED or UNREVIEWED) instead of default based on label; for commit, only commit reports with this status")
)

type create struct {
	*issueParser
	*creator
}

func (create) name() string { return "create" }

func (create) usage() (string, string) {
	const desc = "creates a new vulnerability YAML report"
	return ghIssueArgs, desc
}

func (c *create) setup(ctx context.Context, env environment) error {
	c.creator = new(creator)
	c.issueParser = new(issueParser)
	return setupAll(ctx, env, c.creator, c.issueParser)
}

func (c *create) close() error {
	return closeAll(c.creator)
}

func (c *create) run(ctx context.Context, input any) error {
	iss := input.(*issues.Issue)
	return c.reportFromIssue(ctx, iss)
}
