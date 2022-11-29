// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"fmt"
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
	YAMLDir = "data/reports"

	// ExcludedDir is the name of the directory in the vulndb repo that
	// contains excluded reports.
	ExcludedDir = "data/excluded"
)

func GetAllExisting(repo *git.Repository) (byIssue map[int]*Report, byFile map[string]*Report, err error) {
	defer derrors.Wrap(&err, "GetAllExisting")
	root, err := gitrepo.Root(repo)
	if err != nil {
		return nil, nil, err
	}

	byIssue = make(map[int]*Report)
	byFile = make(map[string]*Report)

	if err = root.Files().ForEach(func(f *object.File) error {
		name := f.Name
		if !(filepath.Dir(name) == YAMLDir || filepath.Dir(name) == ExcludedDir) ||
			filepath.Ext(name) != ".yaml" {
			return nil
		}

		reader, err := f.Reader()
		if err != nil {
			return err
		}
		d := yaml.NewDecoder(reader)
		d.KnownFields(true)
		var r Report
		if err := d.Decode(&r); err != nil {
			return fmt.Errorf("yaml.Decode: %v", err)
		}

		_, _, iss, err := ParseFilepath(name)
		if err != nil {
			return err
		}

		byFile[name] = &r
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
		for _, alias := range rr.GetAliases() {
			if slices.Contains(r.GetAliases(), alias) {
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
