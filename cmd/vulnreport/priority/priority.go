// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package priority contains utilities for prioritizing vulnerability reports.
package priority

import (
	"fmt"

	"golang.org/x/vulndb/internal/report"
)

type Result struct {
	Priority    Priority
	Reason      string
	NotGo       bool
	NotGoReason string
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

func Analyze(mp string, reportsForModule []*report.Report, modulesToImports map[string]int) *Result {
	sc := stateCounts(reportsForModule)

	notGo, notGoReason := isPossiblyNotGo(len(reportsForModule), sc)
	importers, ok := modulesToImports[mp]
	if !ok {
		return &Result{
			Priority:    Unknown,
			Reason:      fmt.Sprintf("module %s not found", mp),
			NotGo:       notGo,
			NotGoReason: notGoReason,
		}
	}

	priority, reason := priority(mp, importers, sc)
	return &Result{
		Priority:    priority,
		Reason:      reason,
		NotGo:       notGo,
		NotGoReason: notGoReason,
	}
}

func priority(mp string, importers int, sc map[reportState]int) (priority Priority, reason string) {
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
			return High, getReason("and more", "than")
		} else if rev == binary {
			return High, getReason("and as many", "as")
		}

		return Low, getReason("but fewer", "than")
	}

	return Low, importersStr("<")
}

func isPossiblyNotGo(numReports int, sc map[reportState]int) (bool, string) {
	if (float32(sc[excludedNotGo])/float32(numReports))*100 > 20 {
		return true, fmt.Sprintf("more than 20 percent of reports (%d of %d) with this module are NOT_GO_CODE", sc[excludedNotGo], numReports)
	}
	return false, ""
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
		case "NOT_GO_CODE":
			return excludedNotGo
		case "EFFECTIVELY_PRIVATE", "NOT_IMPORTABLE", "LEGACY_FALSE_POSITIVE":
			return excludedBinary
		case "NOT_A_VULNERABILITY", "DEPENDENT_VULNERABILITY":
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
