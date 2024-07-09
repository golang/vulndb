// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	vlog "golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/genericosv"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/triage"
)

type triager interface {
	triage(context.Context, string) error
}

type cveTriager struct {
	report.Fetcher
	pc *pkgsite.Client
}

func (t *cveTriager) triage(ctx context.Context, id string) error {
	cve, err := fetchAs[*cve5.CVERecord](ctx, t, id)
	if err != nil {
		return err
	}

	result, err := triage.RefersToGoModule(ctx, cve, t.pc)
	if err != nil {
		return err
	}
	printResult(id, result)

	return nil
}

type ghsaTriager struct {
	report.Fetcher
}

func (t *ghsaTriager) triage(ctx context.Context, id string) error {
	ghsa, err := fetchAs[*genericosv.Entry](ctx, t, id)
	if err != nil {
		return err
	}

	result := triage.ContainsGoModule(ghsa)
	printResult(id, result)

	return nil
}

func printResult(id string, result *triage.Result) {
	if result == nil {
		vlog.Infof("%s does not appear to be a Go vulnerability", id)
		return
	}
	vlog.Outf("%s is likely a Go vulnerability", id)
	if result.ModulePath != "" {
		vlog.Outf("Module: %s", result.ModulePath)
	}
	if result.PackagePath != "" {
		vlog.Outf("Package: %s", result.PackagePath)
	}
	if result.Reason != "" {
		vlog.Outf("Reason: %s", result.Reason)
	}
}

func fetchAs[T any](ctx context.Context, f report.Fetcher, id string) (T, error) {
	var zero T
	src, err := f.Fetch(ctx, id)
	if err != nil {
		return zero, err
	}
	v, ok := src.(T)
	if !ok {
		return zero, fmt.Errorf("%s cannot be cast as %T", src, zero)
	}
	return v, nil
}

func triageCVEs(ctx context.Context, cves []string) {
	if len(cves) == 0 {
		return
	}
	t := &cveTriager{Fetcher: cve5.NewFetcher(), pc: pkgsite.Default()}
	triageBatch(ctx, t, cves)
}

func triageGHSAs(ctx context.Context, ghsas []string) {
	if len(ghsas) == 0 {
		return
	}
	t := &ghsaTriager{Fetcher: genericosv.NewFetcher()}
	triageBatch(ctx, t, ghsas)
}

func triageBatch(ctx context.Context, t triager, ids []string) {
	for _, id := range ids {
		if err := t.triage(ctx, id); err != nil {
			vlog.Err(err)
		}
	}
}
