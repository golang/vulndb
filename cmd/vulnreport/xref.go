// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"math"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/triage/priority"
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

// xref returns cross-references for a report (information about other reports
// for the same CVE, GHSA, or module), and the priority of a report.
func (x *xref) run(ctx context.Context, input any) (err error) {
	r := input.(*yamlReport)

	if xrefs := x.xref(r); len(xrefs) > 0 {
		log.Out(xrefs)
	} else {
		log.Infof("%s: no xrefs found", r.Filename)
	}

	pr, notGo := x.reportPriority(r.Report)
	log.Outf("%s: priority is %s\n - %s", r.ID, pr.Priority, pr.Reason)
	if notGo != nil {
		log.Outf("%s is likely not Go\n - %s", r.ID, notGo.Reason)
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

	mm, err := env.ModuleMap()
	if err != nil {
		return err
	}
	x.moduleMap = mm

	return nil
}

type xrefer struct {
	rc        *report.Client
	moduleMap map[string]int
}

func (x *xrefer) xref(r *yamlReport) string {
	aliasTitle := fmt.Sprintf("%s: found possible duplicates", r.ID)
	moduleTitle := fmt.Sprintf("%s: found module xrefs", r.ID)
	return x.rc.XRef(r.Report).ToString(aliasTitle, moduleTitle, "")
}

func (x *xrefer) modulePriority(modulePath string) (*priority.Result, *priority.NotGoResult) {
	return priority.Analyze(modulePath, math.MaxInt, x.rc.ReportsByModule(modulePath), x.moduleMap)
}

func (x *xrefer) reportPriority(r *report.Report) (*priority.Result, *priority.NotGoResult) {
	return priority.AnalyzeReport(r, x.rc, x.moduleMap)
}
