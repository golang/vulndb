// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
)

type cveCmd struct {
	*linter
	filenameParser
	noSkip
}

func (cveCmd) name() string { return "cve" }

func (cveCmd) usage() (string, string) {
	const desc = "creates and saves CVE 5.0 record from the provided YAML reports"
	return filenameArgs, desc
}

func (c *cveCmd) setup(ctx context.Context) error {
	c.linter = new(linter)
	return setupAll(ctx, c.linter)
}

func (c *cveCmd) close() error { return nil }

func (c *cveCmd) run(_ context.Context, input any) error {
	r := input.(*yamlReport)
	if err := c.lint(r); err != nil {
		return err
	}
	return r.writeCVE()
}
