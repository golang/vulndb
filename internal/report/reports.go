// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
	"gopkg.in/yaml.v3"
)

var (
	// YAMLDir is the name of the directory in the vulndb repo that
	// contains reports.
	YAMLDir = filepath.Join(dataFolder, reportsFolder)

	// ExcludedDir is the name of the directory in the vulndb repo that
	// contains excluded reports.
	ExcludedDir = filepath.Join(dataFolder, excludedFolder)
)

const (
	dataFolder, reportsFolder, excludedFolder = "data", "reports", "excluded"
)

// All returns all the reports in the repo, indexed by issue and by filename.
func All(repo *git.Repository) (byIssue map[int]*Report, byFile map[string]*Report, err error) {
	defer derrors.Wrap(&err, "All()")
	root, err := gitrepo.Root(repo)
	if err != nil {
		return nil, nil, err
	}

	byIssue = make(map[int]*Report)
	byFile = make(map[string]*Report)

	if err = root.Files().ForEach(func(f *object.File) error {
		if !isYAMLReport(f) {
			return nil
		}

		content, err := f.Contents()
		if err != nil {
			return err
		}
		var r Report
		if err := yaml.Unmarshal([]byte(content), &r); err != nil {
			return err
		}

		_, _, iss, err := ParseFilepath(f.Name)
		if err != nil {
			return err
		}

		byFile[f.Name] = &r
		byIssue[iss] = &r

		return nil
	}); err != nil {
		return nil, nil, err
	}

	return byIssue, byFile, nil
}

// XRef returns cross-references for a report: in this case, a map from
// filenames to aliases (CVE & GHSA IDs) and modules (excluding std and cmd).
func XRef(r *Report, existingByFile map[string]*Report) (matches map[string][]string) {
	mods := make(map[string]bool)
	for _, m := range r.Modules {
		if mod := m.Module; mod != "" && mod != "std" && mod != "cmd" {
			mods[m.Module] = true
		}
	}

	// matches is a map from filename -> alias/module
	matches = make(map[string][]string)
	for fname, rr := range existingByFile {
		for _, alias := range rr.Aliases() {
			if slices.Contains(r.Aliases(), alias) {
				matches[fname] = append(matches[fname], alias)
			}
		}
		for _, m := range rr.Modules {
			if mods[m.Module] {
				k := "Module " + m.Module
				matches[fname] = append(matches[fname], k)
			}
		}
	}
	return matches
}

// Aliases returns a sorted list of all aliases (CVEs and GHSAs) in vulndb,
// including those in the excluded directory.
func Aliases(repo *git.Repository) (_ []string, err error) {
	defer derrors.Wrap(&err, "Aliases()")
	root, err := gitrepo.Root(repo)
	if err != nil {
		return nil, err
	}

	var aliases []string
	if err = root.Files().ForEach(func(f *object.File) error {
		if !isYAMLReport(f) {
			return nil
		}

		content, err := f.Contents()
		if err != nil {
			return err
		}
		var r Report
		if err := yaml.Unmarshal([]byte(content), &r); err != nil {
			return err
		}

		aliases = append(aliases, r.Aliases()...)

		return nil
	}); err != nil {
		return nil, err
	}

	slices.Sort(aliases)
	return aliases, nil
}

func isYAMLReport(f *object.File) bool {
	dir, ext := filepath.Dir(f.Name), filepath.Ext(f.Name)
	return (dir == YAMLDir || dir == ExcludedDir) && ext == ".yaml"
}
