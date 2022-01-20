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
