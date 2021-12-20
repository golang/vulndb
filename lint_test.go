// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/vulndb/internal/report"
)

const reportsDir = "reports"

func TestLintReports(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	if runtime.GOOS == "android" {
		t.Skipf("android builder does not have access to reports/")
	}
	reports, err := ioutil.ReadDir(reportsDir)
	if err != nil {
		t.Fatalf("unable to read reports/: %s", err)
	}
	for _, rf := range reports {
		if rf.IsDir() {
			continue
		}
		t.Run(rf.Name(), func(t *testing.T) {
			fn := filepath.Join(reportsDir, rf.Name())
			lints, err := report.LintFile(fn)
			if err != nil {
				t.Fatalf("vulnlint.LintReport(%q): %s", fn, err)
			}
			if len(lints) > 0 {
				t.Errorf(strings.Join(lints, "\n"))
			}
		})
	}
}
