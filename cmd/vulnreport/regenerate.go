// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/report"
)

type regenerate struct {
	*creator
	*filenameParser
}

func (regenerate) name() string { return "regen" }

func (regenerate) usage() (string, string) {
	const desc = "regenerates reports from source"
	return filenameArgs, desc
}

func (u *regenerate) setup(ctx context.Context, env environment) error {
	u.creator = new(creator)
	u.filenameParser = new(filenameParser)
	return setupAll(ctx, env, u.creator, u.filenameParser)
}

func (u *regenerate) close() error {
	return closeAll(u.creator)
}

func (u *regenerate) skip(input any) string {
	r := input.(*yamlReport)

	// Never re-generate an original report.
	if r.CVEMetadata != nil || r.IsOriginal() {
		return "original report"
	}

	// Usually, we don't auto-regenerate REVIEWED reports, as doing so
	// would likely clobber valuable information.
	if r.IsReviewed() {
		if *force {
			log.Warnf("%s: reviewed; but -f was specified, continuing", r.ID)
			return ""
		}
		return "reviewed; use -f to force"
	}

	return ""
}

func (u *regenerate) run(ctx context.Context, input any) (err error) {
	oldR := input.(*yamlReport)

	for _, note := range oldR.Notes {
		// A note with no type was added by a human.
		if note.Type == report.NoteTypeNone {
			log.Warnf("%s may have been manually edited: %s", oldR.ID, note.Body)
		}
	}

	r, err := u.reportFromMeta(ctx, oldR.meta())
	if err != nil {
		return err
	}

	if !cmp.Equal(r, oldR,
		cmpopts.IgnoreFields(report.SourceMeta{}, "Created"),
		// VulnerableAt can change based on latest published version, so we don't
		// need to update the report if only that changed.
		cmpopts.IgnoreFields(report.Module{}, "VulnerableAt")) {
		return u.write(ctx, r)
	} else {
		log.Infof("%s: re-generating from source does not change report", r.ID)
	}

	return nil
}

func (r *yamlReport) meta() *reportMeta {
	var modulePath string
	if len(r.Modules) > 0 {
		modulePath = r.Modules[0].Module
	}

	return &reportMeta{
		id:           r.ID,
		modulePath:   modulePath,
		aliases:      r.Aliases(),
		reviewStatus: r.ReviewStatus,
		unexcluded:   r.Unexcluded,
	}
}
