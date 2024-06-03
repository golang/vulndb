// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/report"
)

type createExcluded struct {
	*creator
	*committer
	*issueParser
}

func (createExcluded) name() string { return "create-excluded" }

func (createExcluded) usage() (string, string) {
	const desc = "creates and commits reports for Github issues marked excluded"
	return "", desc
}

func (c *createExcluded) close() (err error) {
	defer func() {
		if cerr := closeAll(c.creator); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	err = c.commit(c.created...)
	return err
}

func (c *createExcluded) setup(ctx context.Context, env environment) error {
	c.creator = new(creator)
	c.committer = new(committer)
	c.issueParser = new(issueParser)
	return setupAll(ctx, env, c.creator, c.committer, c.issueParser)
}

func (c *createExcluded) run(ctx context.Context, input any) (err error) {
	iss := input.(*issues.Issue)
	return c.reportFromIssue(ctx, iss)
}

func (c *createExcluded) skip(input any) string {
	iss := input.(*issues.Issue)

	if !isExcluded(iss) {
		return "not excluded"
	}

	if c.assignee != "" && iss.Assignee != c.assignee {
		return fmt.Sprintf("assigned to %s, not %s", iss.Assignee, c.assignee)
	}

	return c.creator.skip(iss)
}

func isExcluded(iss *issues.Issue) bool {
	for _, er := range report.ExcludedReasons {
		if iss.HasLabel(er.ToLabel()) {
			return true
		}
	}
	return false
}
