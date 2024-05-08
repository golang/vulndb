// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
)

type osvCmd struct {
	*linter
	filenameParser
}

func (osvCmd) name() string { return "osv" }

func (osvCmd) usage() (string, string) {
	const desc = "converts YAML reports to OSV JSON and writes to data/osv"
	return filenameArgs, desc
}

func (o *osvCmd) setup(ctx context.Context) error {
	o.linter = new(linter)
	return setupAll(ctx, o.linter)
}

func (o *osvCmd) close() error { return nil }

func (o *osvCmd) run(ctx context.Context, filename string) error {
	r, err := o.readLinted(filename)
	if err != nil {
		return err
	}
	return writeOSV(r)
}
