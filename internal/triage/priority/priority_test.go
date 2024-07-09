// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package priority

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/report"
)

var (
	notGo1 = &report.Report{
		Excluded: "NOT_GO_CODE",
	}
	reviewed1 = &report.Report{
		ReviewStatus: report.Reviewed,
	}
	reviewed2 = &report.Report{
		ReviewStatus: report.Reviewed,
	}
	reviewedBinary = &report.Report{
		ReviewStatus: report.Reviewed,
		Unexcluded:   "NOT_IMPORTABLE",
	}
	unreviewed1 = &report.Report{
		ReviewStatus: report.Unreviewed,
	}
	binary1 = &report.Report{
		Excluded: "NOT_IMPORTABLE",
	}
	binary2 = &report.Report{
		Excluded: "EFFECTIVELY_PRIVATE",
	}
	binary3 = &report.Report{
		Excluded: "LEGACY_FALSE_POSITIVE",
	}
	unreviewedBinary = &report.Report{
		ReviewStatus: report.Unreviewed,
		Unexcluded:   "NOT_IMPORTABLE",
	}
	notAVuln1 = &report.Report{
		Excluded: "NOT_A_VULNERABILITY",
	}
	dependent1 = &report.Report{
		Excluded: "DEPENDENT_VULNERABILITY",
	}
)

func TestAnalyze(t *testing.T) {
	for _, tc := range []struct {
		name             string
		module           string
		reportsForModule []*report.Report
		modulesToImports map[string]int
		want             *Result
		wantNotGo        *NotGoResult
	}{
		{
			name:             "unknown priority",
			module:           "example.com/module",
			modulesToImports: map[string]int{},
			want: &Result{
				Priority: Unknown,
				Reason:   "module example.com/module not found",
			},
		},
		{
			name:             "low priority",
			module:           "example.com/module",
			reportsForModule: []*report.Report{},
			modulesToImports: map[string]int{"example.com/module": 99},
			want: &Result{
				Priority: Low,
				Reason:   "example.com/module has 99 importers (< 100)",
			},
		},
		{
			name:             "high priority",
			module:           "example.com/module",
			reportsForModule: []*report.Report{},
			modulesToImports: map[string]int{"example.com/module": 100},
			want: &Result{
				Priority: High,
				Reason:   "example.com/module has 100 importers (>= 100) and as many reviewed (0) as likely-binary reports (0)",
			},
		},
		{
			name:             "high priority more reviewed",
			module:           "example.com/module",
			reportsForModule: []*report.Report{reviewed1, reviewed2, binary1},
			modulesToImports: map[string]int{"example.com/module": 101},
			want: &Result{
				Priority: High,
				Reason:   "example.com/module has 101 importers (>= 100) and more reviewed (2) than likely-binary reports (1)",
			},
		},
		{
			name:   "low priority more binaries",
			module: "example.com/module",
			reportsForModule: []*report.Report{
				reviewed1,
				binary1, binary2, binary3,
				unreviewed1, notAVuln1, dependent1, // ignored
			},
			modulesToImports: map[string]int{"example.com/module": 101},
			want: &Result{
				Priority: Low,
				Reason:   "example.com/module has 101 importers (>= 100) but fewer reviewed (1) than likely-binary reports (3)",
			},
		},
		{
			name:   "unexcluded unreviewed considered binaries",
			module: "example.com/module",
			reportsForModule: []*report.Report{
				reviewed1, reviewedBinary, // reviewed
				binary1, binary2, unreviewedBinary, // binary
				unreviewed1, notAVuln1, dependent1, // ignored
			},
			modulesToImports: map[string]int{"example.com/module": 101},
			want: &Result{
				Priority: Low,
				Reason:   "example.com/module has 101 importers (>= 100) but fewer reviewed (2) than likely-binary reports (3)",
			},
		},
		{
			name:             "low priority and not Go",
			module:           "example.com/module",
			reportsForModule: []*report.Report{notGo1, reviewed1, binary1, unreviewed1},
			modulesToImports: map[string]int{"example.com/module": 99},
			want: &Result{
				Priority: Low,
				Reason:   "example.com/module has 99 importers (< 100)",
			},
			wantNotGo: &NotGoResult{
				Reason: "more than 20 percent of reports (1 of 4) with this module are NOT_GO_CODE",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, gotNotGo := Analyze(tc.module, tc.reportsForModule, tc.modulesToImports)
			want := tc.want
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("result mismatch (-want, +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantNotGo, gotNotGo); diff != "" {
				t.Errorf("not go mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
