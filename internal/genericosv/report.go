// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genericosv

import (
	"fmt"
	"sort"
	"strings"

	osvschema "github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/version"
)

// ToReport converts OSV into a Go Report with the given ID.
func (osv *Entry) ToReport(goID string, pc *proxy.Client) *report.Report {
	r := &report.Report{
		ID:          goID,
		Summary:     osv.Summary,
		Description: osv.Details,
	}
	addNote := func(note string) {
		r.Notes = append(r.Notes, note)
	}
	addAlias := func(alias string) {
		switch {
		case cveschema5.IsCVE(alias):
			r.CVEs = append(r.CVEs, alias)
		case ghsa.IsGHSA(alias):
			r.GHSAs = append(r.GHSAs, alias)
		default:
			addNote(fmt.Sprintf("create: found alias %s that is not a GHSA or CVE", alias))
		}
	}
	addAlias(osv.ID)
	for _, alias := range osv.Aliases {
		addAlias(alias)
	}
	for _, ref := range osv.References {
		r.References = append(r.References, convertRef(ref))
	}
	r.Modules = affectedToModules(osv.Affected, addNote, pc)
	r.Credits = convertCredits(osv.Credits)
	r.Fix(pc)
	if lints := r.Lint(pc); len(lints) > 0 {
		slices.Sort(lints)
		for _, lint := range lints {
			addNote(fmt.Sprintf("lint: %s", lint))
		}
	}
	return r
}

type addNoteFunc func(string)

func affectedToModules(as []osvschema.Affected, addNote addNoteFunc, pc *proxy.Client) []*report.Module {
	var modules []*report.Module
	for _, a := range as {
		if a.Package.Ecosystem != osvschema.EcosystemGo {
			continue
		}

		modules = append(modules, &report.Module{
			Module:   a.Package.Name,
			Versions: convertVersions(a.Ranges, addNote),
		})
	}

	for _, m := range modules {
		extractImportPath(m, pc)
		m.FixVersions(pc)
	}

	sortModules(modules)
	return modules
}

// extractImportPath checks if the module m's "module" path is actually
// an import path. If so, it adds the import path to the packages list
// and fixes the module path. Modifies m.
//
// Does nothing if the module path is already correct, or isn't recognized
// by the proxy at all.
func extractImportPath(m *report.Module, pc *proxy.Client) {
	path := m.Module
	modulePath := pc.FindModule(m.Module)
	if modulePath == "" || // path doesn't contain a module, needs human review
		path == modulePath { // path is already a module, no action needed
		return
	}
	m.Module = modulePath
	m.Packages = append(m.Packages, &report.Package{Package: path})
}

func sortModules(ms []*report.Module) {
	sort.Slice(ms, func(i, j int) bool {
		m1, m2 := ms[i], ms[j]
		// Break ties by lowest affected version, assuming the version list is sorted.
		if m1.Module == m2.Module {
			vr1, vr2 := m1.Versions, m2.Versions
			if len(vr1) == 0 {
				return true
			} else if len(vr2) == 0 {
				return false
			}
			return version.Before(first(vr1), first(vr2))
		}
		return m1.Module < m2.Module
	})
}

func first(vrs []report.VersionRange) string {
	for _, vr := range vrs {
		for _, v := range []string{vr.Introduced, vr.Fixed} {
			if v != "" {
				return v
			}
		}
	}
	return ""
}

func convertVersions(rs []osvschema.Range, addNote addNoteFunc) []report.VersionRange {
	var vrs []report.VersionRange
	for _, r := range rs {
		for _, e := range r.Events {
			var vr report.VersionRange
			switch {
			case e.Introduced == "0":
				continue
			case e.Introduced != "":
				vr.Introduced = e.Introduced
			case e.Fixed != "":
				vr.Fixed = e.Fixed
			default:
				addNote(fmt.Sprintf("create: unsupported version range event %#v", e))
				continue
			}
			vrs = append(vrs, vr)
		}
	}
	return vrs
}

func convertRef(ref osvschema.Reference) *report.Reference {
	return &report.Reference{
		Type: osv.ReferenceType(ref.Type),
		URL:  ref.URL,
	}
}

func convertCredits(cs []osvschema.Credit) []string {
	var credits []string
	for _, c := range cs {
		credit := c.Name
		if len(c.Contact) != 0 {
			credit = fmt.Sprintf("%s (%s)", c.Name, strings.Join(c.Contact, ","))
		}
		credits = append(credits, credit)
	}
	return credits
}
