// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"context"
	"errors"
	"fmt"
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
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/database"
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
	reportsDir  = "data/reports"
	excludedDir = "data/excluded"
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
			// Check that a correct OSV file was generated for each YAML report.
			if r.Excluded == "" {
				generated := database.GenerateOSVEntry(filename, time.Time{}, r)
				current, err := database.ReadOSV(fmt.Sprintf("data/osv/%v.json", generated.ID))
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(generated, current, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("data/osv/%v.json does not match report:\n%v", generated.ID, diff)
				}
			}
			if r.CVEMetadata != nil {
				generated, err := report.ToCVE5(filename)
				if err != nil {
					t.Fatal(err)
				}
				cvePath := fmt.Sprintf("data/cve/v5/%v.json", report.GetGoIDFromFilename(filename))
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

const vulnDBURL = "https://vuln.go.dev"

// This test fails with this error on TryBots:
// ListIDs(): ListIDs(): Get "https://vuln.go.dev/ID/index.json": dial tcp
// 34.117.213.18:443: connect: no route to host
//
// TODO(https://go.dev/issue/56139): add this test as a deployment step.
func TestMissingReports(t *testing.T) {
	t.Skip()

	ctx := context.Background()
	dbClient, err := vulnc.NewClient([]string{vulnDBURL}, vulnc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := dbClient.ListIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		f := fmt.Sprintf("data/osv/%s.json", id)
		if _, err := os.Stat(f); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s was deleted; use the withdrawn field instead to remove reports. See doc/format.md for details.\n", f)
			} else {
				t.Fatal(err)
			}
		}
	}
}
