// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"

	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

var (
	update = flag.Bool("update", false, "for symbols, populate the FixLinks field for each module")
)

type symbolsCmd struct{ filenameParser }

func (symbolsCmd) name() string { return "symbols" }

func (symbolsCmd) usage() (string, string) {
	const desc = "finds and populates possible vulnerable symbols for a given report"
	return filenameArgs, desc
}

func (s *symbolsCmd) setup(ctx context.Context) error { return nil }

func (s *symbolsCmd) close() error { return nil }

func (s *symbolsCmd) run(ctx context.Context, filename string) (err error) {
	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	if err = symbols.Populate(r, *update); err != nil {
		return err
	}

	return r.Write(filename)
}
