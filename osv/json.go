// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package osv implements the OSV shared vulnerability
// format, as defined by https://github.com/ossf/osv-schema.
//
// As this package is intended for use with the Go vulnerability
// database, only the subset of features which are used by that
// database are implemented (for instance, only the SEMVER affected
// range type is implemented).
package osv

import (
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/internal/report"
)

// DBIndex contains a mapping of vulnerable packages to the
// last time a new vulnerability was added to the database.
// TODO: this is probably not the correct place to put this
// type, since it's not really an OSV/CVF thing, but rather
// vulndb implementatiion detail.
type DBIndex map[string]time.Time

type AffectsRangeType string

const (
	TypeUnspecified AffectsRangeType = "UNSPECIFIED"
	TypeGit         AffectsRangeType = "GIT"
	TypeSemver      AffectsRangeType = "SEMVER"
)

type Ecosystem string

const GoEcosystem Ecosystem = "Go"

type Package struct {
	Name      string    `json:"name"`
	Ecosystem Ecosystem `json:"ecosystem"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type AffectsRange struct {
	Type   AffectsRangeType `json:"type"`
	Events []RangeEvent     `json:"events"`
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

func (ar AffectsRange) containsSemver(v string) bool {
	if ar.Type != TypeSemver {
		return false
	}
	if len(ar.Events) == 0 {
		return true
	}

	// Strip and then add the semver prefix so we can support bare versions,
	// versions prefixed with 'v', and versions prefixed with 'go'.
	v = canonicalizeSemverPrefix(v)

	var affected bool
	for _, e := range ar.Events {
		if !affected && e.Introduced != "" {
			affected = e.Introduced == "0" || semver.Compare(v, addSemverPrefix(e.Introduced)) >= 0
		} else if e.Fixed != "" {
			affected = semver.Compare(v, addSemverPrefix(e.Fixed)) < 0
		}
	}

	return affected
}

type Affects []AffectsRange

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

func generateAffectedRanges(versions []report.VersionRange) Affects {
	a := AffectsRange{Type: TypeSemver}
	if len(versions) == 0 || versions[0].Introduced == "" {
		a.Events = append(a.Events, RangeEvent{Introduced: "0"})
	}
	for _, v := range versions {
		if v.Introduced != "" {
			v.Introduced = canonicalizeSemverPrefix(v.Introduced)
			a.Events = append(a.Events, RangeEvent{Introduced: removeSemverPrefix(semver.Canonical(v.Introduced))})
		}
		if v.Fixed != "" {
			v.Fixed = canonicalizeSemverPrefix(v.Fixed)
			a.Events = append(a.Events, RangeEvent{Fixed: removeSemverPrefix(semver.Canonical(v.Fixed))})
		}
	}
	return Affects{a}
}

func (a Affects) AffectsSemver(v string) bool {
	if len(a) == 0 {
		// No ranges implies all versions are affected
		return true
	}
	var semverRangePresent bool
	for _, r := range a {
		if r.Type != TypeSemver {
			continue
		}
		semverRangePresent = true
		if r.containsSemver(v) {
			return true
		}
	}
	// If there were no semver ranges present we
	// assume that all semvers are affected, similarly
	// to how to we assume all semvers are affected
	// if there are no ranges at all.
	return !semverRangePresent
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Affected struct {
	Package           Package           `json:"package"`
	Ranges            Affects           `json:"ranges,omitempty"`
	DatabaseSpecific  DatabaseSpecific  `json:"database_specific"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

type DatabaseSpecific struct {
	URL string `json:"url"`
}

type EcosystemSpecific struct {
	Symbols []string `json:"symbols,omitempty"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
}

// Entry represents a OSV style JSON vulnerability database
// entry
type Entry struct {
	ID         string      `json:"id"`
	Published  time.Time   `json:"published"`
	Modified   time.Time   `json:"modified"`
	Withdrawn  *time.Time  `json:"withdrawn,omitempty"`
	Aliases    []string    `json:"aliases,omitempty"`
	Details    string      `json:"details"`
	Affected   []Affected  `json:"affected"`
	References []Reference `json:"references,omitempty"`
}

func generateAffected(importPath string, versions []report.VersionRange, goos, goarch, symbols []string, url string) Affected {
	return Affected{
		Package: Package{
			Name:      importPath,
			Ecosystem: GoEcosystem,
		},
		Ranges:           generateAffectedRanges(versions),
		DatabaseSpecific: DatabaseSpecific{URL: url},
		EcosystemSpecific: EcosystemSpecific{
			GOOS:    goos,
			GOARCH:  goarch,
			Symbols: symbols,
		},
	}
}

func Generate(id string, url string, r report.Report) (Entry, []string) {
	importPath := r.Module
	if r.Package != "" {
		importPath = r.Package
	}
	moduleMap := make(map[string]bool)
	if r.Stdlib {
		moduleMap["stdlib"] = true
	} else {
		moduleMap[r.Module] = true
	}
	lastModified := r.Published
	if r.LastModified != nil {
		lastModified = *r.LastModified
	}
	entry := Entry{
		ID:        id,
		Published: r.Published,
		Modified:  lastModified,
		Withdrawn: r.Withdrawn,
		Details:   r.Description,
		Affected:  []Affected{generateAffected(importPath, r.Versions, r.OS, r.Arch, r.Symbols, url)},
	}

	for _, additional := range r.AdditionalPackages {
		additionalPath := additional.Module
		if additional.Package != "" {
			additionalPath = additional.Package
		}
		if !r.Stdlib {
			moduleMap[additional.Module] = true
		}
		entry.Affected = append(entry.Affected, generateAffected(additionalPath, additional.Versions, r.OS, r.Arch, additional.Symbols, url))
	}

	if r.Links.PR != "" {
		entry.References = append(entry.References, Reference{Type: "FIX", URL: r.Links.PR})
	}
	if r.Links.Commit != "" {
		entry.References = append(entry.References, Reference{Type: "FIX", URL: r.Links.Commit})
	}
	for _, link := range r.Links.Context {
		entry.References = append(entry.References, Reference{Type: "WEB", URL: link})
	}

	if r.CVE != "" {
		entry.Aliases = []string{r.CVE}
	}

	var modules []string
	for module := range moduleMap {
		modules = append(modules, module)
	}

	return entry, modules
}
