// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

type lint struct {
	*linter
	filenameParser
}

func (lint) name() string { return "lint" }

func (lint) usage() (string, string) {
	const desc = "lints vulnerability YAML reports"
	return filenameArgs, desc
}

func (l *lint) setup(ctx context.Context) error {
	l.linter = new(linter)
	return setupAll(ctx, l.linter)
}

func (l *lint) close() error { return nil }

func (l *lint) run(ctx context.Context, filename string) (err error) {
	_, err = l.readLinted(filename)
	return err
}

type linter struct {
	pc *proxy.Client
}

func (l *linter) setup(_ context.Context) error {
	l.pc = proxy.NewDefaultClient()
	return nil
}

func (l *linter) lint(r *report.Report) error {
	if lints := r.Lint(l.pc); len(lints) > 0 {
		return fmt.Errorf("%v has %d lint warnings:%s%s", r.ID, len(lints), listItem, strings.Join(lints, listItem))
	}
	return nil
}

func (l *linter) readLinted(filename string) (*report.Report, error) {
	r, err := report.ReadStrict(filename)
	if err != nil {
		return nil, err
	}
	if err := l.lint(r); err != nil {
		return nil, err
	}
	return r, nil
}
