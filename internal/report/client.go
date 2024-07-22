// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

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

	cve5Dir = filepath.Join(dataFolder, "cve", "v5")
)

const (
	dataFolder, reportsFolder, excludedFolder = "data", "reports", "excluded"
)

// Client is a client for accessing vulndb reports from a git repository.
type Client struct {
	byFile   map[string]*Report
	byIssue  map[int]*Report
	byAlias  map[string][]*File
	byModule map[string][]*File
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

type Xrefs struct {
	// map from aliases to files
	Aliases map[string][]*File
	// map from modules to files
	Modules map[string][]*File
}

func fprintMap(out io.Writer, m map[string][]*File) {
	sortedKeys := func(m map[string][]*File) []string {
		s := slices.Clone(maps.Keys(m))
		slices.Sort(s)
		return s
	}

	for _, k := range sortedKeys(m) {
		fs := m[k]
		fmt.Fprintf(out, "- %s appears in %d other report(s):\n", k, len(fs))
		for _, f := range fs {
			fmt.Fprintf(out, "  - %s    (https://github.com/golang/vulndb/issues/%d)", f.Filename, f.IssNum)
			if f.Report.IsExcluded() {
				fmt.Fprintf(out, "    %v", f.Report.Excluded)
			}
			fmt.Fprintf(out, "\n")
		}
	}
}

func (xs *Xrefs) ToString(aliasTitle, moduleTitle, noneMessage string) string {
	if len(xs.Modules) == 0 && len(xs.Aliases) == 0 {
		return noneMessage
	}

	out := &strings.Builder{}

	if len(xs.Aliases) != 0 {
		fmt.Fprint(out, aliasTitle+"\n")
		fprintMap(out, xs.Aliases)
		if len(xs.Modules) != 0 {
			fmt.Fprintf(out, "\n")
		}
	}

	if len(xs.Modules) != 0 {
		fmt.Fprint(out, moduleTitle+"\n")
		fprintMap(out, xs.Modules)
	}

	return out.String()
}

type File struct {
	Filename string
	IssNum   int
	*Report
}

// XRef returns cross-references for a report.
func (c *Client) XRef(r *Report) *Xrefs {
	x := &Xrefs{
		Aliases: make(map[string][]*File),
		Modules: make(map[string][]*File),
	}

	for _, alias := range r.Aliases() {
		for _, f := range c.byAlias[alias] {
			if r.ID == f.Report.ID {
				continue
			}
			x.Aliases[alias] = append(x.Aliases[alias], f)
		}
	}

	for _, m := range r.Modules {
		if m.IsFirstParty() {
			continue
		}
		for _, f := range c.byModule[m.Module] {
			if r.ID == f.Report.ID {
				continue
			}
			x.Modules[m.Module] = append(x.Modules[m.Module], f)
		}
	}

	return x
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
	var rs []*Report
	for _, f := range c.byAlias[alias] {
		rs = append(rs, f.Report)
	}
	return rs
}

// ReportsByModule returns a list of reports in vulndb with the given
// module.
func (c *Client) ReportsByModule(module string) []*Report {
	var rs []*Report
	for _, f := range c.byModule[module] {
		rs = append(rs, f.Report)
	}
	return rs
}

// AliasHasReport returns whether the given alias exists in vulndb.
func (c *Client) AliasHasReport(alias string) bool {
	_, ok := c.byAlias[alias]
	return ok
}

func newClient() *Client {
	return &Client{
		byIssue:  make(map[int]*Report),
		byFile:   make(map[string]*Report),
		byAlias:  make(map[string][]*File),
		byModule: make(map[string][]*File),
	}
}

func (c *Client) addReports(repo *git.Repository) error {
	root, err := gitrepo.Root(repo)
	if err != nil {
		return err
	}

	return root.Files().ForEach(func(f *object.File) error {
		if !IsYAMLReport(f.Name) {
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

func IsYAMLReport(fname string) bool {
	dir, ext := filepath.Dir(fname), filepath.Ext(fname)
	return (dir == YAMLDir || dir == ExcludedDir) && ext == ".yaml"
}

func (c *Client) addReport(filename string, r *Report) error {
	_, _, iss, err := ParseFilepath(filename)
	if err != nil {
		return err
	}

	f := &File{
		Filename: filename,
		IssNum:   iss,
		Report:   r,
	}

	c.byFile[filename] = r
	c.byIssue[iss] = r
	for _, alias := range r.Aliases() {
		c.byAlias[alias] = append(c.byAlias[alias], f)
	}
	for _, m := range r.Modules {
		c.byModule[m.Module] = append(c.byModule[m.Module], f)
	}

	return nil
}
