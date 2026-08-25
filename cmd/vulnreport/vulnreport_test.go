// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"golang.org/x/vulndb/internal/issues"
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
