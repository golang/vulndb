// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
)

type osvCmd struct {
	*linter
	*fileWriter
	*filenameParser
	noSkip
}

func (osvCmd) name() string { return "osv" }

func (osvCmd) usage() (string, string) {
	const desc = "converts YAML reports to OSV JSON and writes to data/osv"
	return filenameArgs, desc
}

func (o *osvCmd) setup(ctx context.Context, env environment) error {
	o.linter = new(linter)
	o.filenameParser = new(filenameParser)
	o.fileWriter = new(fileWriter)
	return setupAll(ctx, env, o.linter, o.filenameParser, o.fileWriter)
}

func (o *osvCmd) close() error { return nil }

func (o *osvCmd) run(_ context.Context, input any) error {
	r := input.(*yamlReport)
	if err := o.lint(r); err != nil {
		return err
	}
	return o.writeOSV(r)
}
