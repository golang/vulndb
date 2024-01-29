// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/report"
)

// setDates sets the PublishedDate of the report at filename to the oldest
// commit date in the repo that contains that file. (It may someday also set a
// last-modified date, hence the plural.) Since it looks at the commits from
// origin/master, it will only work for reports that are already submitted. Thus
// it isn't useful to run when you're working on a report, only at a later time.
//
// It isn't crucial to run this for every report, because the same logic exists
// in gendb, ensuring that every report has a PublishedDate before being
// transformed into a DB entry. The advantage of using this command is that
// the dates become permanent (if you create and submit a CL after running it).
//
// This intentionally does not set the LastModified of the report: While the
// publication date of a report may be expected not to change, the modification
// date can. Always using the git history as the source of truth for the
// last-modified date avoids confusion if the report YAML and the git history
// disagree.
func setDates(_ context.Context, filename string, dates map[string]gitrepo.Dates) (err error) {
	defer derrors.Wrap(&err, "setDates(%q)", filename)

	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if !r.Published.IsZero() {
		return nil
	}
	d, ok := dates[filename]
	if !ok {
		return fmt.Errorf("can't find git repo commit dates for %q", filename)
	}
	r.Published = d.Oldest
	return r.Write(filename)
}
