// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"
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
