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
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/report"
)

type xref struct {
	*xrefer
	*filenameParser
	noSkip
}

func (xref) name() string { return "xref" }

func (xref) usage() (string, string) {
	const desc = "prints cross references for YAML reports"
	return filenameArgs, desc
}

func (x *xref) setup(ctx context.Context, env environment) error {
	x.xrefer = new(xrefer)
	x.filenameParser = new(filenameParser)
	return setupAll(ctx, env, x.xrefer, x.filenameParser)
}

func (x *xref) close() error { return nil }

// xref returns cross-references for a report: Information about other reports
// for the same CVE, GHSA, or module.
func (x *xref) run(ctx context.Context, input any) (err error) {
	r := input.(*yamlReport)

	if xrefs := x.xref(r); len(xrefs) > 0 {
		log.Outf("xrefs for %s:%s", r.Filename, xrefs)
	} else {
		log.Infof("%s: no xrefs found", r.Filename)
	}

	return nil
}

func (x *xrefer) setup(ctx context.Context, env environment) (err error) {
	repo, err := env.ReportRepo(ctx)
	if err != nil {
		return err
	}
	rc, err := report.NewClient(repo)
	if err != nil {
		return err
	}
	x.rc = rc
	return nil
}

type xrefer struct {
	rc *report.Client
}

func (x *xrefer) xref(r *yamlReport) string {
	out := &strings.Builder{}
	matches := x.rc.XRef(r.Report)
	delete(matches, r.Filename)
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
	return out.String()
}

func sorted[E constraints.Ordered](s []E) []E {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
