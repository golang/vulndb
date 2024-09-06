// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/version"
)

var (
	// osvDir is the name of the directory in the vulndb repo that
	// contains reports.
	OSVDir = "data/osv"

	// SchemaVersion is used to indicate which version of the OSV schema a
	// particular vulnerability was exported with.
	SchemaVersion = "1.3.1"
)

func (r *Report) nonGoExplanation() string {
	const nonGoExplanation = `NOTE: The source advisory for this report
contains additional versions that could not be automatically mapped to standard
Go module versions.

(If this is causing false-positive reports from vulnerability scanners,
please suggest an edit to the report.)

The additional affected modules and versions are: `
	vs := r.nonGoVersionsStr()
	if vs != "" {
		return fmt.Sprintf("%s%s", nonGoExplanation, vs)
	}
	return ""
}

func (r *Report) nonGoVersionsStr() string {
	var vs []string
	for _, m := range r.Modules {
		if s := m.NonGoVersions.verboseString(); s != "" {
			vs = append(vs, fmt.Sprintf("%s %s", m.Module, s))
		}
	}
	return strings.Join(vs, "; ") + "."
}

func (v Versions) verboseString() string {
	if len(v) == 0 {
		return ""
	}

	pairs := v.collectRangePairs()
	var vs []string
	for _, p := range pairs {
		var s string
		if p.intro == "" && p.fixed == "" {
			// If neither field is set, the vuln applies to all versions.
			// Leave it blank, the template will render it properly.
			s = ""
		} else if p.intro == "" {
			s = "before " + p.fixed
		} else if p.fixed == "" {
			s = p.intro + " and later"
		} else {
			s = "from " + p.intro + " before " + p.fixed
		}
		vs = append(vs, s)
	}

	return strings.Join(vs, ", ")
}

// A pair is like an osv.Range, but each pair is a self-contained 2-tuple
// (introduced version, fixed version).
type pair struct {
	intro, fixed string
}

func (vs Versions) collectRangePairs() []pair {
	var (
		ps []pair
		p  pair
	)
	addPrefix := func(s *string) {
		const semverPrefix = "v"
		if *s != "" && version.IsValid(*s) {
			*s = semverPrefix + *s
		}
	}

	for _, v := range vs {
		if v.IsIntroduced() {
			// We expected Introduced and Fixed to alternate, but if
			// p.intro != "", then they don't.
			// Keep going in that case, ignoring the first Introduced.
			p.intro = v.Version
			if p.intro == "0" {
				p.intro = ""
			}
			addPrefix(&p.intro)
		}
		if v.IsFixed() {
			p.fixed = v.Version
			addPrefix(&p.fixed)
			ps = append(ps, p)
			p = pair{}
		}
	}
	return ps
}

// ToOSV creates an osv.Entry for a report.
// lastModified is the time the report should be considered to have
// been most recently modified.
func (r *Report) ToOSV(lastModified time.Time) (osv.Entry, error) {
	var credits []osv.Credit
	for _, credit := range r.Credits {
		credits = append(credits, osv.Credit{
			Name: credit,
		})
	}

	entry := osv.Entry{
		ID:            r.ID,
		Published:     osv.Time{Time: r.Published},
		Modified:      osv.Time{Time: lastModified},
		Withdrawn:     r.Withdrawn,
		Related:       r.Related,
		Summary:       toParagraphs(r.Summary.String()),
		Credits:       credits,
		SchemaVersion: SchemaVersion,
		DatabaseSpecific: &osv.DatabaseSpecific{
			URL:          idstr.GoAdvisory(r.ID),
			ReviewStatus: osv.ReviewStatus(r.ReviewStatus),
		},
	}

	hasNonGoVersions := false
	for _, m := range r.Modules {
		affected, err := toAffected(m)
		if err != nil {
			return osv.Entry{}, err
		}
		entry.Affected = append(entry.Affected, affected)
		if len(m.NonGoVersions) != 0 {
			hasNonGoVersions = true
		}
	}
	for _, ref := range r.References {
		entry.References = append(entry.References, osv.Reference{
			Type: ref.Type,
			URL:  ref.URL,
		})
	}
	entry.Aliases = r.Aliases()

	// If the report has no description, use the summary for now.
	// TODO(https://go.dev/issues/61201): Remove this once pkgsite and
	// govulncheck can robustly display summaries in place of details.
	details := r.Description.String()
	if details == "" {
		details = r.Summary.String()
	}

	// Add an explanation about non-Go versions if applicable.
	if hasNonGoVersions && r.IsUnreviewed() {
		if !strings.HasSuffix(details, ".") {
			details = fmt.Sprintf("%s.", details)
		}
		details = fmt.Sprintf("%s\n\n%s", details, r.nonGoExplanation())
	}
	entry.Details = toParagraphs(details)

	return entry, nil
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

func (v *Version) ToRangeEvent() (osv.RangeEvent, error) {
	switch t := v.Type; t {
	case VersionTypeFixed:
		return osv.RangeEvent{Fixed: v.Version}, nil
	case VersionTypeIntroduced:
		return osv.RangeEvent{Introduced: v.Version}, nil
	default:
		return osv.RangeEvent{}, fmt.Errorf("version type %s not supported for osv.RangeEvent", t)
	}
}

var zeroEvent = osv.RangeEvent{Introduced: "0"}

func (vs Versions) ToSemverRanges() ([]osv.Range, error) {
	t := osv.RangeTypeSemver
	a, err := vs.ToRangesWithType(t)
	if err != nil {
		return nil, err
	} else if a == nil {
		return []osv.Range{{Type: t, Events: []osv.RangeEvent{zeroEvent}}}, nil
	}
	return a, nil
}

func (vs Versions) ToRangesWithType(t osv.RangeType) ([]osv.Range, error) {
	if len(vs) == 0 {
		return nil, nil
	}

	a := osv.Range{Type: t}
	if !vs[0].IsIntroduced() {
		a.Events = append(a.Events, zeroEvent)
	}
	for _, v := range vs {
		re, err := v.ToRangeEvent()
		if err != nil {
			return nil, err
		}
		a.Events = append(a.Events, re)
	}
	return []osv.Range{a}, nil
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

func toAffected(m *Module) (osv.Affected, error) {
	name := m.Module
	switch name {
	case stdlib.ModulePath:
		name = osv.GoStdModulePath
	case stdlib.ToolchainModulePath:
		name = osv.GoCmdModulePath
	}
	ranges, err := m.Versions.ToSemverRanges()
	if err != nil {
		return osv.Affected{}, err
	}
	customRanges, err := m.NonGoVersions.ToRangesWithType(osv.RangeTypeEcosystem)
	if err != nil {
		return osv.Affected{}, err
	}
	return osv.Affected{
		Module: osv.Module{
			Path:      name,
			Ecosystem: osv.GoEcosystem,
		},
		Ranges: ranges,
		EcosystemSpecific: &osv.EcosystemSpecific{
			Packages:     toOSVPackages(m.Packages),
			CustomRanges: customRanges,
		},
	}, nil
}
