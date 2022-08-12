// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package database generates the vulnerability database.
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/stdlib"
)

const (
	dbURL = "https://pkg.go.dev/vuln/"

	// idDirectory is the name of the directory that contains entries
	// listed by their IDs.
	idDirectory = "ID"

	// yamlDir is the name of the directory in the vulndb repo that
	// contains reports.
	yamlDir = "data/reports"

	// stdFileName is the name of the .json file in the vulndb repo
	// that will contain info on standard library vulnerabilities.
	stdFileName = "stdlib"
)

func Generate(ctx context.Context, repoDir, jsonDir string) (err error) {
	defer derrors.Wrap(&err, "Generate(%q)", repoDir)
	yamlFiles, err := ioutil.ReadDir(filepath.Join(repoDir, yamlDir))
	if err != nil {
		return fmt.Errorf("can't read %q: %s", yamlDir, err)
	}

	repo, err := gitrepo.Open(ctx, repoDir)
	if err != nil {
		return err
	}

	commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.MainReference, "reports/")
	if err != nil {
		return err
	}

	jsonVulns := map[string][]osv.Entry{}
	var entries []osv.Entry
	for _, f := range yamlFiles {
		if !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		r, err := report.Read(filepath.Join(repoDir, yamlDir, f.Name()))
		if err != nil {
			return err
		}
		if r.Excluded != "" {
			// We may want to include excluded reports in the database
			// at some point, with a bit indicating that they are
			// uninteresting, but omit them for now.
			continue
		}

		yamlPath := filepath.Join(yamlDir, f.Name())
		dates, ok := commitDates[yamlPath]
		if !ok {
			return fmt.Errorf("can't find git repo commit dates for %q", yamlPath)
		}
		// If a report contains a published field, consider it
		// the authoritative source of truth. Otherwise, set
		// the published field from the git history.
		if r.Published.IsZero() {
			r.Published = dates.Oldest
		}
		// Always set the last_modified field based on git history.
		// The alternative is to possibly miss modifications to any
		// report with a checked-in last_modified field.
		if newest := dates.Newest; !dates.Oldest.Equal(newest) {
			r.LastModified = &newest
		}

		if lints := r.Lint(yamlPath); len(lints) > 0 {
			return fmt.Errorf("vuln.Lint: %v", lints)
		}

		name := strings.TrimSuffix(filepath.Base(f.Name()), filepath.Ext(f.Name()))
		linkName := fmt.Sprintf("%s%s", dbURL, name)
		entry, paths := GenerateOSVEntry(name, linkName, *r)
		for _, path := range paths {
			jsonVulns[path] = append(jsonVulns[path], entry)
		}
		entries = append(entries, entry)
	}

	index := make(client.DBIndex, len(jsonVulns))
	for path, vulns := range jsonVulns {
		outPath := filepath.Join(jsonDir, path)
		content, err := json.Marshal(vulns)
		if err != nil {
			return fmt.Errorf("failed to marshal json: %s", err)
		}
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory %q: %s", filepath.Dir(outPath), err)
		}
		if err := ioutil.WriteFile(outPath+".json", content, 0644); err != nil {
			return fmt.Errorf("failed to write %q: %s", outPath+".json", err)
		}
		for _, v := range vulns {
			if v.Modified.After(index[path]) || v.Published.After(index[path]) {
				index[path] = v.Modified
			}
		}
	}

	indexJSON, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("failed to marshal index json: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(jsonDir, "index.json"), indexJSON, 0644); err != nil {
		return fmt.Errorf("failed to write index: %s", err)
	}

	// Write a directory containing entries by ID.
	idDir := filepath.Join(jsonDir, idDirectory)
	if err := os.MkdirAll(idDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %v", idDir, err)
	}
	var idIndex []string
	for _, e := range entries {
		outPath := filepath.Join(idDir, e.ID+".json")
		content, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("failed to marshal json: %v", err)
		}
		if err := ioutil.WriteFile(outPath, content, 0644); err != nil {
			return fmt.Errorf("failed to write %q: %v", outPath, err)
		}
		idIndex = append(idIndex, e.ID)
	}

	// Write an index.json in the ID directory with a list of all the IDs.
	idIndexJSON, err := json.Marshal(idIndex)
	if err != nil {
		return fmt.Errorf("failed to marshal index json: %s", err)
	}
	if err := ioutil.WriteFile(filepath.Join(idDir, "index.json"), idIndexJSON, 0644); err != nil {
		return fmt.Errorf("failed to write index: %s", err)
	}
	return nil
}

// GenerateOSVEntry create an osv.Entry for a report. In addition to the report, it
// takes the ID for the vuln and a URL that will point to the entry in the vuln DB.
// It returns the osv.Entry and a list of module paths that the vuln affects.
func GenerateOSVEntry(id, url string, r report.Report) (osv.Entry, []string) {
	lastModified := r.Published
	if r.LastModified != nil {
		lastModified = *r.LastModified
	}
	entry := osv.Entry{
		ID:        id,
		Published: r.Published,
		Modified:  lastModified,
		Withdrawn: r.Withdrawn,
		Details:   r.Description,
	}

	moduleMap := make(map[string]bool)
	for _, p := range r.Packages {
		importPath := p.Module
		if p.Package != "" {
			importPath = p.Package
		}
		if stdlib.Contains(p.Module) {
			moduleMap[stdFileName] = true
		} else {
			moduleMap[p.Module] = true
		}
		entry.Affected = append(entry.Affected, generateAffected(importPath, p.Versions, r.OS, r.Arch, p.AllSymbols(), url))
	}

	if r.Links.Advisory != "" {
		entry.References = append(entry.References, osv.Reference{Type: "ADVISORY", URL: r.Links.Advisory})
	}
	if r.Links.PR != "" {
		entry.References = append(entry.References, osv.Reference{Type: "FIX", URL: r.Links.PR})
	}
	if r.Links.Commit != "" {
		entry.References = append(entry.References, osv.Reference{Type: "FIX", URL: r.Links.Commit})
	}
	for _, link := range r.Links.Context {
		entry.References = append(entry.References, osv.Reference{Type: "WEB", URL: link})
	}
	for _, aliasLink := range r.GetAliasLinks() {
		entry.References = append(entry.References, osv.Reference{Type: "WEB", URL: aliasLink})
	}
	entry.Aliases = r.GetAliases()

	var modules []string
	for module := range moduleMap {
		modules = append(modules, module)
	}
	return entry, modules
}

func generateAffectedRanges(versions []report.VersionRange) osv.Affects {
	a := osv.AffectsRange{Type: osv.TypeSemver}
	if len(versions) == 0 || versions[0].Introduced == "" {
		a.Events = append(a.Events, osv.RangeEvent{Introduced: "0"})
	}
	for _, v := range versions {
		if v.Introduced != "" {
			a.Events = append(a.Events, osv.RangeEvent{Introduced: v.Introduced.Canonical()})
		}
		if v.Fixed != "" {
			a.Events = append(a.Events, osv.RangeEvent{Fixed: v.Fixed.Canonical()})
		}
	}
	return osv.Affects{a}
}

func generateAffected(importPath string, versions []report.VersionRange, goos, goarch, symbols []string, url string) osv.Affected {
	return osv.Affected{
		Package: osv.Package{
			Name:      importPath,
			Ecosystem: osv.GoEcosystem,
		},
		Ranges:           generateAffectedRanges(versions),
		DatabaseSpecific: osv.DatabaseSpecific{URL: url},
		EcosystemSpecific: osv.EcosystemSpecific{
			GOOS:    goos,
			GOARCH:  goarch,
			Symbols: symbols,
		},
	}
}
