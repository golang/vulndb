// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

type AffectsRangeType int

const (
	TypeUnspecified AffectsRangeType = iota
	TypeGit
	TypeSemver
)

type Ecosystem string

const GoEcosystem Ecosystem = "go"

type Package struct {
	Name      string
	Ecosystem Ecosystem
}

type AffectsRange struct {
	Type       AffectsRangeType
	Introduced string
	Fixed      string
}

func (ar AffectsRange) containsSemver(v string) bool {
	if ar.Type != TypeSemver {
		return false
	}

	return (ar.Introduced == "" || semver.Compare(v, ar.Introduced) >= 0) &&
		(ar.Fixed == "" || semver.Compare(v, ar.Fixed) < 0)
}

type Affects struct {
	Ranges []AffectsRange `json:",omitempty"`
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
	Symbols []string `json:",omitempty"`
	GOOS    []string `json:",omitempty"`
	GOARCH  []string `json:",omitempty"`
	URL     string
}

type Reference struct {
	Type string
	URL  string
}

// Entry represents a OSV style JSON vulnerability database
// entry
type Entry struct {
	ID         string
	Published  time.Time
	Modified   time.Time
	Withdrawn  *time.Time `json:",omitempty"`
	Aliases    []string   `json:",omitempty"`
	Package    Package
	Details    string
	Affects    Affects
	References []Reference `json:",omitempty"`
	Extra      struct {
		Go GoSpecific
	}
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
		Extra: struct{ Go GoSpecific }{
			Go: GoSpecific{
				Symbols: r.Symbols,
				GOOS:    r.OS,
				GOARCH:  r.Arch,
				URL:     url,
			},
		},
	}

	if r.Links.PR != "" {
		entry.References = append(entry.References, Reference{Type: "code review", URL: r.Links.PR})
	}
	if r.Links.Commit != "" {
		entry.References = append(entry.References, Reference{Type: "fix", URL: r.Links.Commit})
	}
	for _, link := range r.Links.Context {
		entry.References = append(entry.References, Reference{Type: "misc", URL: link})
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
		entryCopy.Extra.Go.Symbols = additional.Symbols
		entryCopy.Affects = generateAffects(additional.Versions)

		entries = append(entries, entryCopy)
	}

	return entries
}
