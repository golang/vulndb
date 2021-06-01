// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package osv implements the <name-pending> shared vulnerability
// format, with the Go specific extensions, as defined by
// https://tinyurl.com/vuln-json.
//
// As this package is intended for use with the Go vulnerability
// database, only the subset of features which are used by that
// database are implemented (for instance, only the SEMVER affected
// range type is implemented).
//
// The format of the Go specific "extra" JSON object is as follows:
//
//   {
//     "symbols": [ string ],
//     "goos": [ string ],
//     "goarch": [ string ],
//     "url": string
//   }
package osv

import (
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/report"
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

type AffectsRange struct {
	Type       AffectsRangeType `json:"type"`
	Introduced string           `json:"introduced"`
	Fixed      string           `json:"fixed"`
}

func (ar AffectsRange) containsSemver(v string) bool {
	if ar.Type != TypeSemver {
		return false
	}

	return (ar.Introduced == "" || semver.Compare(v, ar.Introduced) >= 0) &&
		(ar.Fixed == "" || semver.Compare(v, ar.Fixed) < 0)
}

type Affects struct {
	Ranges []AffectsRange `json:"ranges,omitempty"`
}

func generateAffects(versions []report.VersionRange) Affects {
	a := Affects{}
	for _, v := range versions {
		a.Ranges = append(a.Ranges, AffectsRange{
			Type:       TypeSemver,
			Introduced: v.Introduced,
			Fixed:      v.Fixed,
		})
	}
	return a
}

func (a Affects) AffectsSemver(v string) bool {
	if len(a.Ranges) == 0 {
		// No ranges implies all versions are affected
		return true
	}
	var semverRangePresent bool
	for _, r := range a.Ranges {
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

type GoSpecific struct {
	Symbols []string `json:"symbols,omitempty"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	URL     string   `json:"url"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Entry represents a OSV style JSON vulnerability database
// entry
type Entry struct {
	ID                string      `json:"id"`
	Published         time.Time   `json:"published"`
	Modified          time.Time   `json:"modified"`
	Withdrawn         *time.Time  `json:"withdrawn,omitempty"`
	Aliases           []string    `json:"aliases,omitempty"`
	Package           Package     `json:"package"`
	Details           string      `json:"details"`
	Affects           Affects     `json:"affects"`
	References        []Reference `json:"references,omitempty"`
	EcosystemSpecific GoSpecific  `json:"ecosystem_specific"`
}

func Generate(id string, url string, r report.Report) []Entry {
	importPath := r.Module
	if r.Package != "" {
		importPath = r.Package
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
		Package: Package{
			Name:      importPath,
			Ecosystem: GoEcosystem,
		},
		Details: r.Description,
		Affects: generateAffects(r.Versions),
		EcosystemSpecific: GoSpecific{
			Symbols: r.Symbols,
			GOOS:    r.OS,
			GOARCH:  r.Arch,
			URL:     url,
		},
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

	entries := []Entry{entry}

	// It would be better if this was just a recursive thing maybe?
	for _, additional := range r.AdditionalPackages {
		entryCopy := entry
		additionalImportPath := additional.Module
		if additional.Package != "" {
			additionalImportPath = additional.Package
		}
		entryCopy.Package.Name = additionalImportPath
		entryCopy.EcosystemSpecific.Symbols = additional.Symbols
		entryCopy.Affects = generateAffects(additional.Versions)

		entries = append(entries, entryCopy)
	}

	return entries
}
