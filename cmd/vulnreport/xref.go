// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	vlog "golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/report"
)

type xref struct {
	*xrefer
	filenameParser
	noSkip
}

func (xref) name() string { return "xref" }

func (xref) usage() (string, string) {
	const desc = "prints cross references for YAML reports"
	return filenameArgs, desc
}

func (x *xref) setup(ctx context.Context) error {
	x.xrefer = new(xrefer)
	return setupAll(ctx, x.xrefer)
}

func (x *xref) close() error { return nil }

// xref returns cross-references for a report: Information about other reports
// for the same CVE, GHSA, or module.
func (x *xref) run(ctx context.Context, input any) (err error) {
	r := input.(*yamlReport)

	vlog.Out(r.filename)
	xrefs, err := x.xref(r)
	if err != nil {
		return err
	}
	vlog.Out(xrefs)
	return nil
}

func (x *xrefer) setup(ctx context.Context) error {
	localRepo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		return err
	}
	rc, err := report.NewClient(localRepo)
	if err != nil {
		return err
	}
	x.rc = rc
	return nil
}

type xrefer struct {
	rc *report.Client
}

func (x *xrefer) xref(r *yamlReport) (string, error) {
	out := &strings.Builder{}
	matches := x.rc.XRef(r.Report)
	delete(matches, r.filename)
	// This sorts as CVEs, GHSAs, and then modules.
	for _, fname := range sorted(maps.Keys(matches)) {
		for _, id := range sorted(matches[fname]) {
			fmt.Fprintf(out, "\n%v appears in %v", id, fname)
			if r, ok := x.rc.Report(fname); ok {
				if r.IsExcluded() {
					fmt.Fprintf(out, "  %v", r.Excluded)
				}
			}
		}
	}
	return out.String(), nil
}

func (x *xrefer) xrefCount(mp string) (excluded, regular, notGoCode int) {
	for _, r := range x.rc.ReportsByModule(mp) {
		if r.IsExcluded() {
			if r.Excluded == "NOT_GO_CODE" {
				notGoCode++
			}
			excluded++
		} else {
			regular++
		}
	}
	return excluded, regular, notGoCode
}

func sorted[E constraints.Ordered](s []E) []E {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
