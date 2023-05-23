// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRoundTrip(t *testing.T) {
	// A report shouldn't change after being read and then written.
	in := filepath.Join("testdata", "report.yaml")
	r, err := Read(in)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.yaml")
	if err := r.Write(out); err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestUnknownField(t *testing.T) {
	_, err := Read(filepath.Join("testdata", "unknown-field.yaml"))
	const want = "not found"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got %v, want error containing %q", err, want)
	}
}

func TestGetYAMLFilename(t *testing.T) {
	tests := []struct {
		name string
		r    *Report
		goID string
		want string
	}{
		{
			name: "normal",
			r:    &Report{},
			goID: "GO-1999-0001",
			want: "data/reports/GO-1999-0001.yaml",
		},
		{
			name: "excluded",
			r:    &Report{Excluded: "NOT_IMPORTABLE"},
			goID: "GO-1999-0002",
			want: "data/excluded/GO-1999-0002.yaml",
		},
	}
	for _, test := range tests {
		if got := test.r.YAMLFilename(test.goID); got != test.want {
			t.Errorf("got %s, want %s", got, test.want)
		}
	}
}

func TestParseFilepath(t *testing.T) {
	filepath := "data/reports/GO-1999-0023.yaml"
	wantFolder := "data/reports"
	wantFilename := "GO-1999-0023.yaml"
	wantIssueID := 23

	gotFolder, gotFilename, gotIssueID, err := ParseFilepath(filepath)
	if err != nil {
		t.Fatalf("ParseFilepath(%s) returned unexpected error: %v", filepath, err)
	}
	if wantFolder != gotFolder {
		t.Errorf("ParseFilepath(%s) returned incorrect folder: want %q, got %q", filepath, wantFolder, gotFolder)
	}
	if wantFilename != gotFilename {
		t.Errorf("ParseFilepath(%s) returned incorrect filename: want %q, got %q", filepath, wantFilename, gotFilename)
	}
	if wantIssueID != gotIssueID {
		t.Errorf("ParseFilepath(%s) returned incorrect filename: want %d, got %d", filepath, wantIssueID, gotIssueID)
	}
}
