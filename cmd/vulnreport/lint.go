// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/vulndb/internal/proxy"
)

type lint struct {
	*linter
	*filenameParser
	noSkip
}

func (lint) name() string { return "lint" }

func (lint) usage() (string, string) {
	const desc = "lints vulnerability YAML reports"
	return filenameArgs, desc
}

func (l *lint) setup(ctx context.Context, env environment) error {
	l.linter = new(linter)
	l.filenameParser = new(filenameParser)
	return setupAll(ctx, env, l.linter, l.filenameParser)
}

func (l *lint) close() error { return nil }

func (l *lint) run(_ context.Context, input any) error {
	r := input.(*yamlReport)
	return l.lint(r)
}

type linter struct {
	pxc *proxy.Client
}

func (l *linter) setup(_ context.Context, env environment) error {
	l.pxc = env.ProxyClient()
	return nil
}

func (l *linter) lint(r *yamlReport) error {
	if lints := r.Lint(l.pxc); len(lints) > 0 {
		return fmt.Errorf("%v has %d lint warnings:%s%s", r.ID, len(lints), listItem, strings.Join(lints, listItem))
	}
	return nil
}

func (l *linter) canonicalModule(mp string) string {
	if module, err := l.pxc.FindModule(mp); module != "" && err == nil { // no error
		mp = module
	}
	if module, err := l.pxc.CanonicalAtLatest(mp); module != "" && err == nil { // no error
		mp = module
	}
	return mp
}
