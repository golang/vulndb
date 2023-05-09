// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/report"
)

func TestChecksBash(t *testing.T) {
	t.Skip("TODO(https://go.dev/issue/60077): Unskip once fixed.")
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

func TestLintReports(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	if runtime.GOOS == "android" {
		t.Skipf("android builder does not have access to reports/")
	}
	allFiles := make(map[string]string)
	var reports []string
	for _, dir := range []string{report.YAMLDir, report.ExcludedDir} {
		files, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unable to read %v/: %s", dir, err)
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			if filepath.Ext(file.Name()) != ".yaml" {
				continue
			}
			filename := filepath.Join(dir, file.Name())
			if allFiles[file.Name()] != "" {
				t.Errorf("report appears in multiple locations: %v, %v", allFiles[file.Name()], filename)
			}
			allFiles[file.Name()] = filename
			reports = append(reports, filename)
		}
	}
	// Map from aliases (CVEs/GHSAS) to report paths, used to check for duplicate aliases.
	aliases := make(map[string]string)
	sort.Strings(reports)
	for _, filename := range reports {
		t.Run(filename, func(t *testing.T) {
			r, err := report.Read(filename)
			if err != nil {
				t.Fatal(err)
			}
			lints := r.Lint(filename)
			if len(lints) > 0 {
				t.Errorf(strings.Join(lints, "\n"))
			}
			goID := report.GetGoIDFromFilename(filename)
			for _, alias := range r.GetAliases() {
				if report, ok := aliases[alias]; ok {
					t.Errorf("report %s shares duplicate alias %s with report %s", filename, alias, report)
				} else {
					aliases[alias] = filename
				}
			}
			// Check that a correct OSV file was generated for each YAML report.
			if r.Excluded == "" {
				generated := r.GenerateOSVEntry(goID, time.Time{})
				osvFilename := report.GetOSVFilename(goID)
				current, err := report.ReadOSV(osvFilename)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(generated, current, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("%s does not match report:\n%v", osvFilename, diff)
				}
			}
			if r.CVEMetadata != nil {
				generated, err := r.ToCVE5(goID)
				if err != nil {
					t.Fatal(err)
				}
				cvePath := report.GetCVEFilename(goID)
				current, err := cveschema5.Read(cvePath)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(generated, current, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("%s does not match report:\n%v", cvePath, diff)
				}

			}
		})
	}
}
