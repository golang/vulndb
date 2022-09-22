// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package database generates the vulnerability database.
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/maps"
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

	// osvDir is the name of the directory in the vulndb repo that
	// contains reports.
	osvDir = "data/osv"

	// versionFile is the name of the file in the vulndb repo that
	// tracks the generator version.
	versionFile = "data/version.md"

	// stdFileName is the name of the .json file in the vulndb repo
	// that will contain info on standard library vulnerabilities.
	stdFileName = "stdlib"

	// cmdModule is the name of the module containing Go toolchain
	// binaries.
	cmdModule = "cmd"

	// toolchainFileName is the name of the .json file in the vulndb repo
	// that will contain info on toolchain (cmd/...) vulnerabilities.
	toolchainFileName = "toolchain"
)

func Generate(ctx context.Context, repoDir, jsonDir string, indent bool) (err error) {
	defer derrors.Wrap(&err, "Generate(%q)", repoDir)

	jsonVulns, entries, err := generateEntries(ctx, repoDir)
	if err != nil {
		return err
	}

	index := make(client.DBIndex, len(jsonVulns))
	for modulePath, vulns := range jsonVulns {
		epath, err := client.EscapeModulePath(modulePath)
		if err != nil {
			return err
		}
		if err := writeVulns(filepath.Join(jsonDir, epath), vulns, indent); err != nil {
			return err
		}
		for _, v := range vulns {
			if v.Modified.After(index[modulePath]) {
				index[modulePath] = v.Modified
			}
		}
	}
	if err := WriteJSON(filepath.Join(jsonDir, "index.json"), index, indent); err != nil {
		return err
	}
	if err := writeAliasIndex(jsonDir, entries, indent); err != nil {
		return err
	}
	return writeEntriesByID(filepath.Join(jsonDir, idDirectory), entries, indent)
}

func generateEntries(ctx context.Context, repoDir string) (map[string][]osv.Entry, []osv.Entry, error) {
	repo, err := gitrepo.Open(ctx, repoDir)
	if err != nil {
		return nil, nil, err
	}

	osvFiles, err := os.ReadDir(filepath.Join(repoDir, osvDir))
	if err != nil {
		return nil, nil, fmt.Errorf("can't read %q: %s", osvDir, err)
	}

	commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.HeadReference, osvDir)
	if err != nil {
		return nil, nil, err
	}

	jsonVulns := map[string][]osv.Entry{}
	var entries []osv.Entry
	for _, f := range osvFiles {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		filename := filepath.Join(repoDir, osvDir, f.Name())
		entry, err := ReadOSV(filename)
		if err != nil {
			return nil, nil, err
		}
		dates, ok := commitDates[filename]
		if !ok {
			return nil, nil, fmt.Errorf("can't find git repo commit dates for %q", filename)
		}
		// If a report contains a published field, consider it
		// the authoritative source of truth. Otherwise, set
		// the published field from the git history.
		if entry.Published.IsZero() {
			entry.Published = dates.Oldest
		}
		entry.Modified = dates.Newest
		for _, modulePath := range ModulesForEntry(entry) {
			jsonVulns[modulePath] = append(jsonVulns[modulePath], entry)
		}
		entries = append(entries, entry)
	}
	return jsonVulns, entries, nil
}

// ModulesForEntry returns the list of modules affected by an OSV entry.
func ModulesForEntry(entry osv.Entry) []string {
	mods := map[string]bool{}
	for _, a := range entry.Affected {
		mods[a.Package.Name] = true
	}
	return maps.Keys(mods)
}

func writeVulns(outPath string, vulns []osv.Entry, indent bool) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", filepath.Dir(outPath), err)
	}
	return WriteJSON(outPath+".json", vulns, indent)
}

func writeEntriesByID(idDir string, entries []osv.Entry, indent bool) error {
	// Write a directory containing entries by ID.
	if err := os.MkdirAll(idDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %v", idDir, err)
	}
	var idIndex []string
	for _, e := range entries {
		outPath := filepath.Join(idDir, e.ID+".json")
		if err := WriteJSON(outPath, e, indent); err != nil {
			return err
		}
		idIndex = append(idIndex, e.ID)
	}
	// Write an index.json in the ID directory with a list of all the IDs.
	return WriteJSON(filepath.Join(idDir, "index.json"), idIndex, indent)
}

// Write a JSON file containing a map from alias to GO IDs.
func writeAliasIndex(dir string, entries []osv.Entry, indent bool) error {
	aliasToGoIDs := map[string][]string{}
	for _, e := range entries {
		for _, a := range e.Aliases {
			aliasToGoIDs[a] = append(aliasToGoIDs[a], e.ID)
		}
	}
	return WriteJSON(filepath.Join(dir, "aliases.json"), aliasToGoIDs, indent)
}

func WriteJSON(filename string, value any, indent bool) (err error) {
	defer derrors.Wrap(&err, "writeJSON(%s)", filename)

	j, err := jsonMarshal(value, indent)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, j, 0644)
}

func jsonMarshal(v any, indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

// ReadOSV reads an osv.Entry from a file.
func ReadOSV(filename string) (osv.Entry, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return osv.Entry{}, err
	}
	var entry osv.Entry
	if err := json.Unmarshal(b, &entry); err != nil {
		return osv.Entry{}, fmt.Errorf("%v: %w", filename, err)
	}
	return entry, nil
}

// GenerateOSVEntry create an osv.Entry for a report. In addition to the report, it
// takes the ID for the vuln and a URL that will point to the entry in the vuln DB.
func GenerateOSVEntry(filename string, lastModified time.Time, r *report.Report) osv.Entry {
	id := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	entry := osv.Entry{
		ID:        id,
		Published: r.Published,
		Modified:  lastModified,
		Withdrawn: r.Withdrawn,
		Details:   r.Description,
	}

	linkName := fmt.Sprintf("%s%s", dbURL, id)
	for _, m := range r.Modules {
		entry.Affected = append(entry.Affected, generateAffected(m, linkName))
	}
	for _, ref := range r.References {
		entry.References = append(entry.References, osv.Reference{
			Type: string(ref.Type),
			URL:  ref.URL,
		})
	}
	entry.Aliases = r.GetAliases()
	return entry
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

func generateImports(m *report.Module) (imps []osv.EcosystemSpecificImport) {
	for _, p := range m.Packages {
		syms := append([]string{}, p.Symbols...)
		syms = append(syms, p.DerivedSymbols...)
		sort.Strings(syms)
		imps = append(imps, osv.EcosystemSpecificImport{
			Path:    p.Package,
			GOOS:    p.GOOS,
			GOARCH:  p.GOARCH,
			Symbols: syms,
		})
	}
	return imps
}

func generateAffected(m *report.Module, url string) osv.Affected {
	name := m.Module
	switch name {
	case stdlib.ModulePath:
		name = stdFileName
	case cmdModule:
		name = toolchainFileName
	}
	return osv.Affected{
		Package: osv.Package{
			Name:      name,
			Ecosystem: osv.GoEcosystem,
		},
		Ranges:           generateAffectedRanges(m.Versions),
		DatabaseSpecific: osv.DatabaseSpecific{URL: url},
		EcosystemSpecific: osv.EcosystemSpecific{
			Imports: generateImports(m),
		},
	}
}
