// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"golang.org/x/vulndb/internal/report"
)

type review struct {
	*creator
	*filenameParser
}

func (review) name() string { return "review" }

func (review) usage() (string, string) {
	const desc = "converts unreviewed reports to reviewed"
	return filenameArgs, desc
}

func (u *review) setup(ctx context.Context, env environment) error {
	u.creator = new(creator)
	u.filenameParser = new(filenameParser)
	return setupAll(ctx, env, u.creator, u.filenameParser)
}

func (u *review) close() error {
	return closeAll(u.creator)
}

func (u *review) skip(input any) string {
	r := input.(*yamlReport)

	if r.IsExcluded() {
		return "excluded; use vulnreport unexclude instead"
	}

	if r.IsReviewed() {
		return "already reviewed"
	}

	return ""
}

func (u *review) run(ctx context.Context, input any) (err error) {
	meta := input.(*yamlReport).meta()
	meta.reviewStatus = report.Reviewed

	r, err := u.reportFromMeta(ctx, meta)
	if err != nil {
		return err
	}

	return u.write(ctx, r)
}
