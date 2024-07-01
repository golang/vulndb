// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

var reason = flag.String("reason", "", "the reason this report is being withdrawn")

type withdraw struct {
	*fixer
	*filenameParser
}

func (withdraw) name() string { return "withdraw" }

func (withdraw) usage() (string, string) {
	const desc = "withdraws a report"
	return filenameArgs, desc
}

func (w *withdraw) setup(ctx context.Context, env environment) error {
	if *reason == "" {
		return fmt.Errorf("flag -reason must be provided")
	}
	w.fixer = new(fixer)
	w.filenameParser = new(filenameParser)
	return setupAll(ctx, env, w.fixer, w.filenameParser)
}

func (w *withdraw) close() error {
	return nil
}

func (w *withdraw) skip(input any) string {
	r := input.(*yamlReport)

	if r.IsExcluded() {
		return "excluded; can't be withdrawn"
	}

	if r.Withdrawn != nil {
		return "already withdrawn"
	}

	if r.CVEMetadata != nil {
		return "withdrawing Go-published report not yet supported"
	}

	return ""
}

func (w *withdraw) run(ctx context.Context, input any) (err error) {
	r := input.(*yamlReport)
	r.Withdrawn = &osv.Time{Time: time.Now()}
	r.Summary = "WITHDRAWN: " + r.Summary
	r.Description = report.Description(
		fmt.Sprintf("(This report has been withdrawn with reason: %q). %s",
			*reason, r.Description))
	return w.fixAndWriteAll(ctx, r, false)
}
