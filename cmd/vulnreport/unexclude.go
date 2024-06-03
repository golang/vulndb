// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/report"
)

type unexclude struct {
	*creator
	*filenameParser
}

func (unexclude) name() string { return "unexclude" }

func (unexclude) usage() (string, string) {
	const desc = "converts excluded YAML reports to regular YAML reports"
	return filenameArgs, desc
}

func (u *unexclude) setup(ctx context.Context, env environment) error {
	u.creator = new(creator)
	u.filenameParser = new(filenameParser)
	return setupAll(ctx, env, u.creator, u.filenameParser)
}

func (u *unexclude) close() error {
	return closeAll(u.creator)
}

func (u *unexclude) skip(input any) string {
	r := input.(*yamlReport)

	if !r.IsExcluded() {
		return "not excluded"
	}

	// Usually, we only unexclude reports that are effectively private or not importable.
	if ex := r.Excluded; ex != "EFFECTIVELY_PRIVATE" && ex != "NOT_IMPORTABLE" {
		if *force {
			log.Warnf("%s: excluded for reason %q, but -f was specified, continuing", r.ID, ex)
			return ""
		}
		return fmt.Sprintf("excluded = %s; use -f to force", ex)
	}

	return ""
}

// unexclude converts an excluded report into a regular report.
func (u *unexclude) run(ctx context.Context, input any) (err error) {
	oldR := input.(*yamlReport)

	var modulePath string
	if len(oldR.Modules) > 0 {
		modulePath = oldR.Modules[0].Module
	}

	r, err := u.reportFromMeta(ctx, &reportMeta{
		id:           oldR.ID,
		modulePath:   modulePath,
		aliases:      oldR.Aliases(),
		reviewStatus: report.Unreviewed,
	})
	if err != nil {
		return err
	}
	if err := u.write(ctx, r); err != nil {
		return err
	}

	remove(oldR)
	return nil
}

func remove(r *yamlReport) {
	if err := os.Remove(r.Filename); err != nil {
		log.Errf("%s: could not remove file %s: %v", r.ID, r.Filename, err)
		return
	}
	log.Infof("%s: removed %s", r.ID, r.Filename)
}
