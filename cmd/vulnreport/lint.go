// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

type lint struct {
	pc *proxy.Client

	filenameParser
}

func (lint) name() string { return "lint" }

func (lint) usage() (string, string) {
	const desc = "lints vulnerability YAML reports"
	return filenameArgs, desc
}

func (l *lint) setup(ctx context.Context) error {
	l.pc = proxy.NewDefaultClient()
	return nil
}

func (l *lint) close() error { return nil }

func (l *lint) run(ctx context.Context, filename string) (err error) {
	_, err = report.ReadAndLint(filename, l.pc)
	return err
}
