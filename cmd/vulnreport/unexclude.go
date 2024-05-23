// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/report"
)

type unexclude struct {
	*creator
	filenameParser
}

func (unexclude) name() string { return "unexclude" }

func (unexclude) usage() (string, string) {
	const desc = "converts excluded YAML reports to regular YAML reports"
	return filenameArgs, desc
}

func (u *unexclude) setup(ctx context.Context) error {
	u.creator = new(creator)
	return setupAll(ctx, u.creator)
}

func (u *unexclude) skipReason(r *report.Report) string {
	if !r.IsExcluded() {
		return "not excluded"
	}

	// Usually, we only unexclude reports that are effectively private or not importable.
	if ex := r.Excluded; ex != "EFFECTIVELY_PRIVATE" && ex != "NOT_IMPORTABLE" {
		if *force {
			log.Warnf("report %s is excluded for reason %q, but -f was specified, continuing", r.ID, ex)
			return ""
		}
		return fmt.Sprintf("excluded = %s; use -f to force", ex)
	}

	return ""
}

// unexclude converts an excluded report into a regular report.
func (u *unexclude) run(ctx context.Context, filename string) (err error) {
	oldR, err := report.ReadStrict(filename)
	if err != nil {
		return err
	}

	if reason := u.skipReason(oldR); reason != "" {
		log.Infof("skipping %s (%s)", filename, reason)
		return nil
	}

	var modulePath string
	if len(oldR.Modules) > 0 {
		modulePath = oldR.Modules[0].Module
	}

	if err := u.reportFromMeta(ctx, &reportMeta{
		id:           oldR.ID,
		modulePath:   modulePath,
		aliases:      oldR.Aliases(),
		reviewStatus: report.Unreviewed,
	}); err != nil {
		return err
	}

	remove(filename)
	return nil
}
