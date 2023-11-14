// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/stdlib"
)

var (
	// osvDir is the name of the directory in the vulndb repo that
	// contains reports.
	OSVDir = "data/osv"

	// SchemaVersion is used to indicate which version of the OSV schema a
	// particular vulnerability was exported with.
	SchemaVersion = "1.3.1"
)

// ToOSV creates an osv.Entry for a report.
// lastModified is the time the report should be considered to have
// been most recently modified.
func (r *Report) ToOSV(lastModified time.Time) osv.Entry {
	var credits []osv.Credit
	for _, credit := range r.Credits {
		credits = append(credits, osv.Credit{
			Name: credit,
		})
	}

	var withdrawn *osv.Time
	if r.Withdrawn != nil {
		withdrawn = &osv.Time{Time: *r.Withdrawn}
	}

	// If the report has no description, use the summary for now.
	// TODO(https://go.dev/issues/61201): Remove this once pkgsite and
	// govulncheck can robustly display summaries in place of details.
	details := r.Description
	if details == "" {
		details = Description(r.Summary)
	}

	entry := osv.Entry{
		ID:               r.ID,
		Published:        osv.Time{Time: r.Published},
		Modified:         osv.Time{Time: lastModified},
		Withdrawn:        withdrawn,
		Related:          r.Related,
		Summary:          toParagraphs(r.Summary.String()),
		Details:          toParagraphs(details.String()),
		Credits:          credits,
		SchemaVersion:    SchemaVersion,
		DatabaseSpecific: &osv.DatabaseSpecific{URL: GoAdvisory(r.ID)},
	}

	for _, m := range r.Modules {
		entry.Affected = append(entry.Affected, toAffected(m))
	}
	for _, ref := range r.References {
		entry.References = append(entry.References, osv.Reference{
			Type: ref.Type,
			URL:  ref.URL,
		})
	}
	entry.Aliases = r.Aliases()
	return entry
}

func (r *Report) OSVFilename() string {
	return filepath.Join(OSVDir, r.ID+".json")
}

// ReadOSV reads an osv.Entry from a file.
func ReadOSV(filename string) (entry osv.Entry, err error) {
	derrors.Wrap(&err, "ReadOSV(%s)", filename)
	if err = UnmarshalFromFile(filename, &entry); err != nil {
		return osv.Entry{}, err
	}
	return entry, nil
}

func UnmarshalFromFile(path string, v any) (err error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(content, v); err != nil {
		return err
	}
	return nil
}

// ModulesForEntry returns the list of modules affected by an OSV entry.
func ModulesForEntry(entry osv.Entry) []string {
	mods := map[string]bool{}
	for _, a := range entry.Affected {
		mods[a.Module.Path] = true
	}
	return maps.Keys(mods)
}

func AffectedRanges(versions []VersionRange) []osv.Range {
	a := osv.Range{Type: osv.RangeTypeSemver}
	if len(versions) == 0 || versions[0].Introduced == "" {
		a.Events = append(a.Events, osv.RangeEvent{Introduced: "0"})
	}
	for _, v := range versions {
		if v.Introduced != "" {
			a.Events = append(a.Events, osv.RangeEvent{Introduced: v.Introduced})
		}
		if v.Fixed != "" {
			a.Events = append(a.Events, osv.RangeEvent{Fixed: v.Fixed})
		}
	}
	return []osv.Range{a}
}

var (
	listMarker     = regexp.MustCompile(`([\*\-\+>]|\d+[.\)]) [^\n]+`)
	spaces         = regexp.MustCompile(`[[:space:]]+`)
	paragraphBreak = regexp.MustCompile(`\s*\n{2,}\s*`)
)

// toParagraphs removes unnecessary whitespace (spaces, tabs and newlines) from
// a string, but preserves paragraph breaks (indicated by two consecutive
// newlines), and Markdown-style list breaks.
func toParagraphs(s string) string {
	if len(s) == 0 {
		return ""
	}
	var result strings.Builder
	result.Grow(len(s))
	for i, line := range strings.Split(strings.TrimSpace(s), "\n") {
		// Replace consecutive space characters with single spaces.
		line = spaces.ReplaceAllString(strings.TrimSpace(line), " ")
		// An empty line represents a paragraph break.
		if len(line) == 0 {
			result.WriteString("\n\n")
			continue
		}
		if i > 0 {
			// Preserve line break if the line starts with a Markdown list marker.
			if loc := listMarker.FindStringIndex(line); loc != nil && loc[0] == 0 {
				result.WriteRune('\n')
			} else {
				result.WriteRune(' ')
			}
		}
		result.WriteString(line)
	}
	// Replace instances of 2 or more newlines with exactly two newlines.
	return paragraphBreak.ReplaceAllString(result.String(), "\n\n")
}

func toOSVPackages(pkgs []*Package) (imps []osv.Package) {
	for _, p := range pkgs {
		syms := append([]string{}, p.Symbols...)
		syms = append(syms, p.DerivedSymbols...)
		sort.Strings(syms)
		imps = append(imps, osv.Package{
			Path:    p.Package,
			GOOS:    p.GOOS,
			GOARCH:  p.GOARCH,
			Symbols: syms,
		})
	}
	return imps
}

func toAffected(m *Module) osv.Affected {
	name := m.Module
	switch name {
	case stdlib.ModulePath:
		name = osv.GoStdModulePath
	case stdlib.ToolchainModulePath:
		name = osv.GoCmdModulePath
	}
	return osv.Affected{
		Module: osv.Module{
			Path:      name,
			Ecosystem: osv.GoEcosystem,
		},
		Ranges: AffectedRanges(m.Versions),
		EcosystemSpecific: &osv.EcosystemSpecific{
			Packages: toOSVPackages(m.Packages),
		},
	}
}
