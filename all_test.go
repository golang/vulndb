// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/vulndb/internal/report"
)

func TestChecksBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	cmd := exec.Command(bash, "./checks.bash")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

const (
	reportsDir  = "reports"
	excludedDir = "excluded"
)

func TestLintReports(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	if runtime.GOOS == "android" {
		t.Skipf("android builder does not have access to reports/")
	}
	allFiles := make(map[string]string)
	var reports []string
	for _, dir := range []string{reportsDir, excludedDir} {
		files, err := ioutil.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unable to read %v/: %s", dir, err)
		}
		for _, fi := range files {
			if fi.IsDir() {
				continue
			}
			fn := filepath.Join(dir, fi.Name())
			if allFiles[fi.Name()] != "" {
				t.Errorf("report appears in multiple locations: %v, %v", allFiles[fi.Name()], fn)
			}
			allFiles[fi.Name()] = fn
			reports = append(reports, fn)
		}
	}
	sort.Strings(reports)
	for _, fn := range reports {
		t.Run(fn, func(t *testing.T) {
			r, err := report.Read(fn)
			if err != nil {
				t.Fatal(err)
			}
			switch filepath.Base(filepath.Dir(fn)) {
			case reportsDir:
				if r.Excluded != "" {
					t.Errorf("report in %q must not have excluded set", reportsDir)
				}
			case excludedDir:
				if r.Excluded == "" {
					t.Errorf("report in %q must have excluded set", excludedDir)
				}
			}
			lints := r.Lint(fn)
			if len(lints) > 0 {
				t.Errorf(strings.Join(lints, "\n"))
			}
		})
	}
}
