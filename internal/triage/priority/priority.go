// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package priority contains utilities for prioritizing vulnerability reports.
package priority

import (
	"fmt"
	"strings"

	"golang.org/x/vulndb/internal/report"
)

type Result struct {
	Priority Priority
	Reason   string
}

type NotGoResult struct {
	Reason string
}

type Priority int

func (p Priority) String() string {
	switch p {
	case Unknown:
		return "unknown"
	case High:
		return "high"
	case Low:
		return "low"
	default:
		return fmt.Sprintf("%d", p)
	}
}

const (
	Unknown Priority = iota
	Low
	High
)

// AnalyzeReport returns the results for a report as a whole:
//   - priority is the priority of its highest-priority module
//   - not Go if all modules are not Go
func AnalyzeReport(r *report.Report, rc *report.Client, modulesToImports map[string]int) (*Result, *NotGoResult) {
	var overall Priority
	var reasons []string
	var notGoReasons []string
	for _, m := range r.Modules {
		mp := m.Module
		result, notGo := Analyze(mp, rc.ReportsByModule(mp), modulesToImports)
		if result.Priority > overall {
			overall = result.Priority
		}
		reasons = append(reasons, result.Reason)
		if notGo != nil {
			notGoReasons = append(notGoReasons, notGo.Reason)
		}
	}

	result := &Result{
		Priority: overall, Reason: strings.Join(reasons, "; "),
	}

	// If all modules are not Go, the report is not Go.
	if len(notGoReasons) == len(r.Modules) {
		return result, &NotGoResult{Reason: strings.Join(notGoReasons, "; ")}
	}

	return result, nil
}

func Analyze(mp string, reportsForModule []*report.Report, modulesToImports map[string]int) (*Result, *NotGoResult) {
	sc := stateCounts(reportsForModule)

	notGo := isPossiblyNotGo(len(reportsForModule), sc)
	importers, ok := modulesToImports[mp]
	if !ok {
		return &Result{
			Priority: Unknown,
			Reason:   fmt.Sprintf("module %s not found", mp),
		}, notGo
	}

	return priority(mp, importers, sc), notGo
}

// override takes precedence over all other metrics in determining
// a module's priority.
var override map[string]Priority = map[string]Priority{
	// argo-cd is primarily a binary and usually has correct version
	// information without intervention.
	"github.com/argoproj/argo-cd":    Low,
	"github.com/argoproj/argo-cd/v2": Low,
	// For #3171
	"github.com/containers/common": Low,
}

func priority(mp string, importers int, sc map[reportState]int) *Result {
	if pr, ok := override[mp]; ok {
		return &Result{pr, fmt.Sprintf("%s is in the override list (priority=%s)", mp, pr)}
	}

	const highPriority = 100
	importersStr := func(comp string) string {
		return fmt.Sprintf("%s has %d importers (%s %d)", mp, importers, comp, highPriority)
	}

	if importers >= highPriority {
		rev := sc[reviewed]
		binary := sc[excludedBinary] + sc[unreviewedUnexcluded]
		getReason := func(conj1, conj2 string) string {
			return fmt.Sprintf("%s %s reviewed (%d) %s likely-binary reports (%d)",
				importersStr(">="), conj1, rev, conj2, binary)
		}

		if rev > binary {
			return &Result{High, getReason("and more", "than")}
		} else if rev == binary {
			return &Result{High, getReason("and as many", "as")}
		}

		return &Result{Low, getReason("but fewer", "than")}
	}

	return &Result{Low, importersStr("<")}
}

func isPossiblyNotGo(numReports int, sc map[reportState]int) *NotGoResult {
	if (float32(sc[excludedNotGo])/float32(numReports))*100 > 20 {
		return &NotGoResult{
			Reason: fmt.Sprintf("more than 20 percent of reports (%d of %d) with this module are NOT_GO_CODE", sc[excludedNotGo], numReports),
		}
	}
	return nil
}

type reportState int

const (
	unknownReportState reportState = iota
	reviewed
	unreviewedStandard
	unreviewedUnexcluded
	excludedBinary
	excludedNotGo
	excludedOther
)

func state(r *report.Report) reportState {
	if r.IsExcluded() {
		switch e := r.Excluded; e {
		case report.ExcludedNotGoCode:
			return excludedNotGo
		case report.ExcludedEffectivelyPrivate,
			report.ExcludedNotImportable,
			report.ExcludedLegacyFalsePositive:
			return excludedBinary
		case report.ExcludedNotAVulnerability,
			report.ExcludedDependentVulnerabilty,
			report.ExcludedWithdrawn:
			return excludedOther
		default:
			return unknownReportState
		}
	}

	switch rs := r.ReviewStatus; rs {
	case report.Reviewed:
		return reviewed
	case report.Unreviewed:
		if r.Unexcluded != "" {
			return unreviewedUnexcluded
		}
		return unreviewedStandard
	}

	return unknownReportState
}

func stateCounts(rs []*report.Report) map[reportState]int {
	counts := make(map[reportState]int)
	for _, r := range rs {
		st := state(r)
		if st == unknownReportState {
			panic("could not determine report state for " + r.ID)
		}
		counts[st]++
	}
	return counts
}
