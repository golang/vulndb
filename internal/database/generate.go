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

	"golang.org/x/mod/semver"
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
	yamlDir = "reports"
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
		if r.Published.IsZero() {
			yamlPath := filepath.Join(yamlDir, f.Name())
			dates, ok := commitDates[yamlPath]
			if !ok {
				return fmt.Errorf("can't find git repo commit dates for %q", yamlPath)
			}
			r.Published = dates.Oldest
		}
		if lints := r.Lint(); len(lints) > 0 {
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
	importPath := r.Module
	if r.Package != "" {
		importPath = r.Package
	}
	moduleMap := make(map[string]bool)
	if stdlib.Contains(r.Module) {
		moduleMap["stdlib"] = true
	} else {
		moduleMap[r.Module] = true
	}
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
		Affected:  []osv.Affected{generateAffected(importPath, r.Versions, r.OS, r.Arch, r.AllSymbols(), url)},
	}

	for _, additional := range r.AdditionalPackages {
		additionalPath := additional.Module
		if additional.Package != "" {
			additionalPath = additional.Package
		}
		if !stdlib.Contains(r.Module) {
			moduleMap[additional.Module] = true
		}
		entry.Affected = append(entry.Affected, generateAffected(additionalPath, additional.Versions, r.OS, r.Arch, additional.AllSymbols(), url))
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
	entry.Aliases = r.CVEs

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
			v.Introduced = canonicalizeSemverPrefix(v.Introduced)
			a.Events = append(a.Events, osv.RangeEvent{Introduced: removeSemverPrefix(semver.Canonical(v.Introduced))})
		}
		if v.Fixed != "" {
			v.Fixed = canonicalizeSemverPrefix(v.Fixed)
			a.Events = append(a.Events, osv.RangeEvent{Fixed: removeSemverPrefix(semver.Canonical(v.Fixed))})
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

// removeSemverPrefix removes the 'v' or 'go' prefixes from go-style
// SEMVER strings, for usage in the public vulnerability format.
func removeSemverPrefix(s string) string {
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "go")
	return s
}

// canonicalizeSemverPrefix turns a SEMVER string into the canonical
// representation using the 'v' prefix, as used by the OSV format.
// Input may be a bare SEMVER ("1.2.3"), Go prefixed SEMVER ("go1.2.3"),
// or already canonical SEMVER ("v1.2.3").
func canonicalizeSemverPrefix(s string) string {
	return addSemverPrefix(removeSemverPrefix(s))
}

// addSemverPrefix adds a 'v' prefix to s if it isn't already prefixed
// with 'v' or 'go'. This allows us to easily test go-style SEMVER
// strings against normal SEMVER strings.
func addSemverPrefix(s string) string {
	if !strings.HasPrefix(s, "v") && !strings.HasPrefix(s, "go") {
		return "v" + s
	}
	return s
}
