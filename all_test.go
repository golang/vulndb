// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows

package main

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/triage/priority"
)

func TestChecksBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	// In short mode (used by presubmit checks), only do offline checks.
	var cmd *exec.Cmd
	if testing.Short() {
		cmd = exec.Command(bash, "./checks.bash", "offline")
	} else {
		cmd = exec.Command(bash, "./checks.bash")
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

const cachedProxyURL = "https://proxy.golang.org/cached-only"

func TestLintReports(t *testing.T) {
	if runtime.GOOS == "android" {
		t.Skipf("android builder does not have access to reports/")
	}
	allFiles := make(map[string]string, 1<<12)
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

	// Skip network calls in short mode.
	var lint func(r *report.Report) []string
	if testing.Short() {
		lint = func(r *report.Report) []string {
			return r.LintOffline()
		}
	} else {
		client := http.Client{
			Timeout:   20 * time.Second,
			Transport: http.DefaultTransport,
		}
		pc := proxy.NewClient(&client, cachedProxyURL)
		lint = func(r *report.Report) []string {
			return r.Lint(pc)
		}
	}

	rc, err := report.NewLocalClient(t.Context(), ".")
	if err != nil {
		t.Fatal(err)
	}

	modulesToImports, err := priority.LoadModuleMap()
	if err != nil {
		t.Fatal(err)
	}

	type loadedReport struct {
		path   string
		report *report.Report
	}

	tests := make([]loadedReport, 0, len(reports))
	aliasToIDs := make(map[string][]string)
	for _, filename := range reports {
		r, ok := rc.Report(filename)
		if !ok {
			t.Fatalf("report %s not found in client", filename)
		}
		tests = append(tests, loadedReport{path: filename, report: r})
		for _, alias := range r.Aliases() {
			aliasToIDs[alias] = append(aliasToIDs[alias], r.ID)
		}
	}

	networkSem := make(chan struct{}, 50)
	var seen sync.Map
	for _, lr := range tests {
		t.Run(lr.report.ID, func(t *testing.T) {
			t.Parallel()
			r := lr.report
			if err := r.CheckFilename(lr.path); err != nil {
				t.Error(err)
			}

			// Prevent transient network failures from surfacing as test
			// failures by retrying up to three times, taking the first pass or
			// all three fails.
			// Also use networkSem to make sure that not too many subtests will
			// be using the network at the same time, in case someone runs the
			// test on a machine with high GOMAXPROCS.
			networkSem <- struct{}{}
			var lints []string
			for range 3 {
				if lints = lint(r); len(lints) == 0 {
					break
				}
			}
			<-networkSem
			if len(lints) > 0 {
				t.Error(strings.Join(lints, "\n"))
			}

			for _, alias := range r.Aliases() {
				for _, id := range aliasToIDs[alias] {
					if id != r.ID {
						t.Errorf("report %s shares duplicate alias %s with report %s", lr.path, alias, id)
					}
				}
			}

			// Ensure that each reviewed report has a unique summary.
			if summary := r.Summary.String(); summary != "" && r.IsReviewed() {
				if existingFile, loaded := seen.LoadOrStore(summary, lr.path); loaded {
					t.Errorf("report %s shares duplicate summary %q with report %s", lr.path, summary, existingFile)
				}
			}

			// Ensure that no unreviewed reports are high priority.
			// This can happen because the initial quick triage algorithm
			// doesn't know about all affected modules - just the one
			// listed in the Github issue.
			if r.IsUnreviewed() && !r.IsExcluded() && !r.UnreviewedOK {
				pr, _ := priority.AnalyzeReport(r, rc, modulesToImports)
				if pr.Priority == priority.High {
					t.Errorf("UNREVIEWED report %s is high priority (should be NEEDS_REVIEW or REVIEWED) - reason: %s", lr.path, pr.Reason)
				}
			}

			// Check that a correct OSV file was generated for each YAML report.
			if r.Excluded == "" {
				generated, err := r.ToOSV(time.Time{})
				if err != nil {
					t.Fatal(err)
				}
				osvFilename := r.OSVFilename()
				// TODO(nealpatel): Buffer I/O?
				current, err := report.ReadOSV(osvFilename)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(generated, current, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("%s does not match report:\n%v", osvFilename, diff)
				}
				if err := osvutils.ValidateExceptTimestamps(&current); err != nil {
					t.Error(err)
				}
			}
			if r.CVEMetadata != nil {
				// TODO(nealpatel): Buffer I/O?
				generated, err := cve5.FromReport(r)
				if err != nil {
					t.Fatal(err)
				}
				cvePath := r.CVEFilename()
				// TODO(nealpatel): Buffer I/O?
				current, err := cve5.Read(cvePath)
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
