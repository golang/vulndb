// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
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

// Client is a client for accessing vulndb reports from a git repository.
type Client struct {
	byFile  map[string]*Report
	byIssue map[int]*Report
	byAlias map[string][]*Report
}

// NewClient returns a Client for accessing the reports in
// the given repo, which must contain directories "data/reports"
// and "data/excluded".
func NewClient(repo *git.Repository) (*Client, error) {
	c := newClient()
	if err := c.addReports(repo); err != nil {
		return nil, err
	}
	return c, nil
}

// NewDefaultClient returns a Client that reads reports from
// https://github.com/golang/vulndb.
func NewDefaultClient(ctx context.Context) (*Client, error) {
	const url = "https://github.com/golang/vulndb"
	vulndb, err := gitrepo.Clone(ctx, url)
	if err != nil {
		return nil, err
	}
	return NewClient(vulndb)
}

// NewTestClient returns a Client based on a map from filenames to
// reports.
//
// Intended for testing.
func NewTestClient(filesToReports map[string]*Report) (*Client, error) {
	c := newClient()
	for fname, r := range filesToReports {
		if err := c.addReport(fname, r); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// List returns all reports (regular and excluded), in an
// indeterminate order.
func (c *Client) List() []*Report {
	return maps.Values(c.byFile)
}

// XRef returns cross-references for a report.
// The output, matches, is a map from filenames to aliases (CVE & GHSA IDs)
// and modules (excluding std and cmd).
func (c *Client) XRef(r *Report) (matches map[string][]string) {
	mods := make(map[string]bool)
	for _, m := range r.Modules {
		if mod := m.Module; mod != "" && mod != "std" && mod != "cmd" {
			mods[m.Module] = true
		}
	}

	// matches is a map from filename -> alias/module
	matches = make(map[string][]string)
	for fname, rr := range c.byFile {
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

// Report returns the report with the given filename in vulndb, or
// (nil, false) if not found.
func (c *Client) Report(filename string) (r *Report, ok bool) {
	r, ok = c.byFile[filename]
	return
}

// HasReport returns whether the Github issue id has
// a corresponding report in vulndb.
func (c *Client) HasReport(githubID int) (found bool) {
	_, found = c.byIssue[githubID]
	return
}

// ReportsByAlias returns a list of reports in vulndb with the given
// alias.
func (c *Client) ReportsByAlias(alias string) []*Report {
	return c.byAlias[alias]
}

// AliasHasReport returns whether the given alias exists in vulndb.
func (c *Client) AliasHasReport(alias string) bool {
	_, ok := c.byAlias[alias]
	return ok
}

func newClient() *Client {
	return &Client{
		byIssue: make(map[int]*Report),
		byFile:  make(map[string]*Report),
		byAlias: make(map[string][]*Report),
	}
}

func (c *Client) addReports(repo *git.Repository) error {
	root, err := gitrepo.Root(repo)
	if err != nil {
		return err
	}

	return root.Files().ForEach(func(f *object.File) error {
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

		return c.addReport(f.Name, &r)
	})
}

func isYAMLReport(f *object.File) bool {
	dir, ext := filepath.Dir(f.Name), filepath.Ext(f.Name)
	return (dir == YAMLDir || dir == ExcludedDir) && ext == ".yaml"
}

func (c *Client) addReport(filename string, r *Report) error {
	_, _, iss, err := ParseFilepath(filename)
	if err != nil {
		return err
	}

	c.byFile[filename] = r
	c.byIssue[iss] = r
	for _, alias := range r.Aliases() {
		c.byAlias[alias] = append(c.byAlias[alias], r)
	}

	return nil
}
