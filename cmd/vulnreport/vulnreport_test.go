// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/report"
)

func TestCreate(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name:    "invalid issue id",
			args:    []string{"999"},
			wantErr: true,
		},
		{
			name: "report already exists",
			args: []string{"1"},
		},
		{
			name:        "new report high priority",
			args:        []string{"100"},
			wantErr:     true,
			expectedErr: "ERROR: create: GO-0000-0100: could not fix all errors; requires manual review",
		},
	} {
		runTest(t, &create{}, tc)
	}
}

func TestModulePath(t *testing.T) {
	testCases := []struct {
		title string
		want  string
	}{
		{
			title: "x/vulndb: potential Go vuln in github.com/foo/bar: GHSA-xxxx",
			want:  "github.com/foo/bar",
		},
		{
			title: "x/vulndb: update fixed versions for GO-2026-4513 / duplicate GO-2026-4740",
			want:  "",
		},
		{
			title: "x/vulndb: potential Go vuln in crypto/tls: CVE-2025-0001",
			want:  "crypto/tls",
		},
		{
			title: `x/vulndb: potential Go vuln in "github.com/foo/bar": GHSA-xxxx`,
			want:  "github.com/foo/bar",
		},
		{
			title: "x/vulndb: potential Go vuln in collectd.org: CVE-2021-0000",
			want:  "collectd.org",
		},
		{
			title: "x/vulndb: potential Go vuln in 1234/foo: GHSA-xxxx",
			want:  "",
		},
		{
			title: "x/vulndb: potential Go vuln in 4.15.2/foo: GHSA-xxxx",
			want:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			iss := &issues.Issue{Title: tc.title}
			if got := modulePath(iss); got != tc.want {
				t.Errorf("modulePath(%q) = %q, want %q", tc.title, got, tc.want)
			}
		})
	}
}

func TestCreateSkipFirstParty(t *testing.T) {
	issueWithLabel := &issues.Issue{
		Number: 200,
		State:  "open",
		Labels: []string{labelFirstParty},
	}
	issueWithoutLabel := &issues.Issue{
		Number: 201,
		State:  "open",
	}

	testCases := []struct {
		name    string
		hasArgs bool
		issue   *issues.Issue
		want    string
	}{
		{
			name:    "without args, issue with label",
			hasArgs: false,
			issue:   issueWithLabel,
			want:    "first party",
		},
		{
			name:    "without args, issue without label",
			hasArgs: false,
			issue:   issueWithoutLabel,
			want:    "",
		},
		{
			name:    "with args, issue with label",
			hasArgs: true,
			issue:   issueWithLabel,
			want:    "",
		},
		{
			name:    "with args, issue without label",
			hasArgs: true,
			issue:   issueWithoutLabel,
			want:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &create{
				creator:     &creator{},
				issueParser: &issueParser{},
				hasArgs:     tc.hasArgs,
			}
			if got := c.skip(tc.issue); got != tc.want {
				t.Errorf("c.skip() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCreateSkipWaiting(t *testing.T) {
	issueWithLabel := &issues.Issue{
		Number: 200,
		State:  "open",
		Labels: []string{labelWaiting},
	}
	issueWithoutLabel := &issues.Issue{
		Number: 201,
		State:  "open",
	}

	testCases := []struct {
		name    string
		hasArgs bool
		issue   *issues.Issue
		want    string
	}{
		{
			name:    "without args, issue with label",
			hasArgs: false,
			issue:   issueWithLabel,
			want:    "waiting",
		},
		{
			name:    "without args, issue without label",
			hasArgs: false,
			issue:   issueWithoutLabel,
			want:    "",
		},
		{
			name:    "with args, issue with label",
			hasArgs: true,
			issue:   issueWithLabel,
			want:    "",
		},
		{
			name:    "with args, issue without label",
			hasArgs: true,
			issue:   issueWithoutLabel,
			want:    "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &create{
				creator:     &creator{},
				issueParser: &issueParser{},
				hasArgs:     tc.hasArgs,
			}
			if got := c.skip(tc.issue); got != tc.want {
				t.Errorf("c.skip() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseSkipIssues(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{
			name:    "empty string",
			input:   "",
			want:    []int{},
			wantErr: false,
		},
		{
			name:    "just whitespace",
			input:   "   \t\n  ",
			want:    []int{},
			wantErr: false,
		},
		{
			name:    "single issue",
			input:   "100",
			want:    []int{100},
			wantErr: false,
		},
		{
			name:    "multiple issues",
			input:   "100 200 300",
			want:    []int{100, 200, 300},
			wantErr: false,
		},
		{
			name:    "extra whitespace around issue ids",
			input:   "  100   200 \t 300  ",
			want:    []int{100, 200, 300},
			wantErr: false,
		},
		{
			name:    "invalid non-integer",
			input:   "abc",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			input:   "100 abc 200",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "comma-separated is invalid",
			input:   "100,200,300",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "floating point number",
			input:   "12.34",
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSkipIssues(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseSkipIssues(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseSkipIssues(%q) mismatch (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestSkipIssues(t *testing.T) {
	labelExcluded := report.ExcludedNotGoCode.ToLabel()

	cmds := []struct {
		name  string
		cmd   command
		input func(issueNum int) any
	}{
		{
			name: "create (without args)",
			cmd:  &create{creator: &creator{}, issueParser: &issueParser{}, hasArgs: false},
			input: func(n int) any {
				return &issues.Issue{Number: n, State: "open"}
			},
		},
		{
			name: "create (with args)",
			cmd:  &create{creator: &creator{}, issueParser: &issueParser{}, hasArgs: true},
			input: func(n int) any {
				return &issues.Issue{Number: n, State: "open"}
			},
		},
		{
			name: "create-excluded",
			cmd:  &createExcluded{creator: &creator{}},
			input: func(n int) any {
				return &issues.Issue{Number: n, State: "open", Labels: []string{labelExcluded}}
			},
		},
		{
			name: "triage",
			cmd:  &triage{},
			input: func(n int) any {
				return &issues.Issue{Number: n, State: "open"}
			},
		},
		{
			name: "commit",
			cmd:  &commit{},
			input: func(n int) any {
				return &yamlReport{Report: &report.Report{ID: fmt.Sprintf("GO-2024-%04d", n)}}
			},
		},
	}

	testCases := []struct {
		name          string
		skippedIssues []int
		issueNum      int
		want          string
	}{
		{
			name:          "issue in skipped list",
			skippedIssues: []int{100, 200},
			issueNum:      100,
			want:          "skipping at user request",
		},
		{
			name:          "second issue in skipped list",
			skippedIssues: []int{100, 200},
			issueNum:      200,
			want:          "skipping at user request",
		},
		{
			name:          "issue not in skipped list",
			skippedIssues: []int{100, 200},
			issueNum:      300,
			want:          "",
		},
		{
			name:          "empty skipped list",
			skippedIssues: nil,
			issueNum:      100,
			want:          "",
		},
	}

	for _, c := range cmds {
		for _, tc := range testCases {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				oldSkipped := skippedIssues
				skippedIssues = tc.skippedIssues
				defer func() { skippedIssues = oldSkipped }()

				if got := c.cmd.skip(c.input(tc.issueNum)); got != tc.want {
					t.Errorf("%s: skip() = %q, want %q", c.name, got, tc.want)
				}
			})
		}
	}
}

func TestParseReportIssue(t *testing.T) {
	testCases := []struct {
		name    string
		id      string
		wantIss int
		wantErr bool
	}{
		{
			name:    "valid",
			id:      "GO-2024-0100",
			wantIss: 100,
			wantErr: false,
		},
		{
			name:    "valid single digit",
			id:      "GO-2024-1",
			wantIss: 1,
			wantErr: false,
		},
		{
			name:    "GO-ID-PENDING",
			id:      "GO-ID-PENDING",
			wantIss: 0,
			wantErr: true,
		},
		{
			name:    "non-numeric issue",
			id:      "GO-2024-PENDING",
			wantIss: 0,
			wantErr: true,
		},
		{
			name:    "too few parts",
			id:      "GO-100",
			wantIss: 0,
			wantErr: true,
		},
		{
			name:    "too many parts",
			id:      "GO-2024-100-1",
			wantIss: 0,
			wantErr: true,
		},
		{
			name:    "wrong prefix",
			id:      "CVE-2024-100",
			wantIss: 0,
			wantErr: true,
		},
		{
			name:    "non-numeric year",
			id:      "GO-YYYY-100",
			wantIss: 0,
			wantErr: true,
		},
		{
			name:    "year not 4 digits",
			id:      "GO-24-100",
			wantIss: 0,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotIss, err := parseReportIssue(tc.id)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseReportIssue(%q) err = %v, wantErr %v", tc.id, err, tc.wantErr)
			}
			if gotIss != tc.wantIss {
				t.Errorf("parseReportIssue(%q) = %d, want %d", tc.id, gotIss, tc.wantIss)
			}
		})
	}
}

func TestCreateExcluded(t *testing.T) {
	for _, tc := range []*testCase{
		// TODO(tatianabradley): add test cases
	} {
		runTest(t, &createExcluded{}, tc)
	}
}

func TestCommit(t *testing.T) {
	for _, tc := range []*testCase{
		// TODO(tatianabradley): add test cases
	} {
		runTest(t, &commit{}, tc)
	}
}

func TestCVE(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name: "ok",
			args: []string{"1"},
		},
		{
			name:    "err",
			args:    []string{"4"},
			wantErr: true,
		},
	} {
		runTest(t, &cveCmd{}, tc)
	}
}

func TestTriage(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name: "all",
			// no args
		},
	} {
		runTest(t, &triage{}, tc)
	}
}

func TestFix(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name: "no_change",
			args: []string{"1"},
		},
	} {
		runTest(t, &fix{}, tc)
	}
}

func TestLint(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name: "no_lints",
			args: []string{"1"},
		},
		{
			name:    "found_lints",
			args:    []string{"4"},
			wantErr: true,
		},
	} {
		runTest(t, &lint{}, tc)
	}
}

func TestOSV(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name: "ok",
			args: []string{"1"},
		},
		{
			name:    "err",
			args:    []string{"4"},
			wantErr: true,
		},
	} {
		runTest(t, &osvCmd{}, tc)
	}
}

func TestRegen(t *testing.T) {
	for _, tc := range []*testCase{
		// TODO(tatianabradley): add test cases
	} {
		runTest(t, &regenerate{}, tc)
	}
}

func TestSetDates(t *testing.T) {
	for _, tc := range []*testCase{
		// TODO(tatianabradley): add test cases
	} {
		runTest(t, &setDates{}, tc)
	}
}

func TestSuggest(t *testing.T) {
	for _, tc := range []*testCase{
		// TODO(tatianabradley): add test cases
	} {
		runTest(t, &suggest{}, tc)
	}
}

func TestSymbols(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name: "ok",
		},
		{
			name:    "err",
			args:    []string{"4"},
			wantErr: true,
		},
	} {
		runTest(t, &symbolsCmd{}, tc)
	}
}

func TestUnexclude(t *testing.T) {
	for _, tc := range []*testCase{
		// TODO(tatianabradley): add test cases
	} {
		runTest(t, &unexclude{}, tc)
	}
}

func TestXref(t *testing.T) {
	for _, tc := range []*testCase{
		{
			name: "no_xrefs",
			args: []string{"1"},
		},
		{
			name: "found_xrefs",
			args: []string{"4"},
		},
	} {
		runTest(t, &xref{}, tc)
	}
}
