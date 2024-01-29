// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var (
	updateIssue = flag.Bool("up", false, "for commit, create a CL that updates (doesn't fix) the tracking bug")
)

func commit(ctx context.Context, filename string, ghsaClient *ghsa.Client, pc *proxy.Client, force bool) (err error) {
	defer derrors.Wrap(&err, "commit(%q)", filename)

	// Clean up the report file and lint the result.
	// Stop if there any problems.
	if err := fix(ctx, filename, ghsaClient, pc, force); err != nil {
		return err
	}
	r, err := report.ReadAndLint(filename, pc)
	if err != nil {
		return err
	}
	if hasUnaddressedTodos(r) {
		// Check after fix() as it can add new TODOs.
		return fmt.Errorf("file %q has unaddressed %q fields", filename, "TODO:")
	}

	// Find all derived files (OSV and CVE).
	files := []string{filename}
	if r.Excluded == "" {
		files = append(files, r.OSVFilename())
	}
	if r.CVEMetadata != nil {
		files = append(files, r.CVEFilename())
	}

	// Add the files to git.
	if err := gitAdd(files...); err != nil {
		return err
	}

	// Commit the files, allowing the user to edit the default commit message.
	msg, err := newCommitMsg(r)
	if err != nil {
		return err
	}
	return gitCommit(msg, files...)
}

func newCommitMsg(r *report.Report) (string, error) {
	f, err := r.YAMLFilename()
	if err != nil {
		return "", err
	}

	folder, filename, issueID, err := report.ParseFilepath(f)
	if err != nil {
		return "", err
	}

	issueAction := "Fixes"
	fileAction := "add"
	if *updateIssue {
		fileAction = "update"
		issueAction = "Updates"
	}
	// For now, we need to manually publish the CVE record so the issue
	// should not be auto-closed on add.
	if r.CVEMetadata != nil {
		issueAction = "Updates"
	}

	return fmt.Sprintf(
		"%s: %s %s\n\nAliases: %s\n\n%s golang/vulndb#%d",
		folder, fileAction, filename, strings.Join(r.Aliases(), ", "),
		issueAction, issueID), nil
}

// hasUnaddressedTodos returns true if report has any unaddressed todos in the
// report, i.e. starts with "TODO:".
func hasUnaddressedTodos(r *report.Report) bool {
	is := func(s string) bool { return strings.HasPrefix(s, "TODO:") }
	any := func(ss []string) bool { return slices.IndexFunc(ss, is) >= 0 }

	if is(string(r.Excluded)) {
		return true
	}
	for _, m := range r.Modules {
		if is(m.Module) {
			return true
		}
		for _, v := range m.Versions {
			if is(string(v.Introduced)) {
				return true
			}
			if is(string(v.Fixed)) {
				return true
			}
		}
		if is(string(m.VulnerableAt)) {
			return true
		}
		for _, p := range m.Packages {
			if is(p.Package) || is(p.SkipFix) || any(p.Symbols) || any(p.DerivedSymbols) {
				return true
			}
		}
	}
	for _, ref := range r.References {
		if is(ref.URL) {
			return true
		}
	}
	if any(r.CVEs) || any(r.GHSAs) {
		return true
	}
	return is(r.Summary.String()) || is(r.Description.String()) || any(r.Credits)
}
