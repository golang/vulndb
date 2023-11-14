// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genericosv

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	osvschema "github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/mod/module"
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
		Summary:     report.Summary(osv.Summary),
		Description: osv.Details,
	}
	addAlias := func(alias string) {
		switch {
		case cveschema5.IsCVE(alias):
			r.CVEs = append(r.CVEs, alias)
		case ghsa.IsGHSA(alias):
			r.GHSAs = append(r.GHSAs, alias)
		default:
			r.Notes = append(r.Notes, &report.Note{
				Body: fmt.Sprintf("found alias %s that is not a GHSA or CVE", alias),
				Type: report.NoteTypeCreate,
			})
		}
	}
	addAlias(osv.ID)
	for _, alias := range osv.Aliases {
		addAlias(alias)
	}

	r.Modules = affectedToModules(osv.Affected, pc)

	for _, ref := range osv.References {
		r.References = append(r.References, convertRef(ref))
	}
	fixRefs(r)

	r.Credits = convertCredits(osv.Credits)

	r.Fix(pc)
	return r
}

func affectedToModules(as []osvschema.Affected, pc *proxy.Client) []*report.Module {
	var modules []*report.Module
	for _, a := range as {
		if a.Package.Ecosystem != osvschema.EcosystemGo {
			continue
		}

		versions, unsupportedVersions := convertVersions(a.Ranges)
		modules = append(modules, &report.Module{
			Module:              a.Package.Name,
			Versions:            versions,
			UnsupportedVersions: unsupportedVersions,
		})
	}

	for _, m := range modules {
		extractImportPath(m, pc)
		if ok := fixMajorVersion(m, pc); !ok {
			addIncompatible(m, pc)
		}
		canonicalize(m, pc)
	}

	modules = merge(modules)

	// Fix the versions *after* the modules have been merged.
	for _, m := range modules {
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
	modulePath, err := pc.FindModule(m.Module)
	if err != nil || // path doesn't contain a module, needs human review
		path == modulePath { // path is already a module, no action needed
		return
	}
	m.Module = modulePath
	m.Packages = append(m.Packages, &report.Package{Package: path})
}

// fixMajorVersion corrects the major version prefix of the module
// path if possible.
// Returns true if the major version was already correct or could be
// fixed.
// For now, it gives up if it encounters various problems and
// special cases (see comments inline).
func fixMajorVersion(m *report.Module, pc *proxy.Client) (ok bool) {
	if strings.HasPrefix(m.Module, "gopkg.in/") {
		return false // don't attempt to fix gopkg.in modules
	}
	// If there is no "introduced" version, don't attempt to fix
	// major version.
	// Example: example.com/module is fixed at 2.2.2. This likely means
	// that example.com/module is vulnerable at all versions and
	// example.com/module/v2 is vulnerable up to 2.2.2.
	// Changing example.com/module to example.com/module/v2 would lose
	// information.
	hasIntroduced := func(m *report.Module) bool {
		for _, vr := range m.Versions {
			if vr.Introduced != "" {
				return true
			}
		}
		return false
	}
	if !hasIntroduced(m) {
		return false
	}
	wantMajor, ok := commonMajor(m.Versions)
	if !ok { // inconsistent major version, don't attempt to fix
		return false
	}
	prefix, major, ok := module.SplitPathVersion(m.Module)
	if !ok { // couldn't parse module path, don't attempt to fix
		return false
	}
	if major == wantMajor {
		return true // nothing to do
	}
	fixed := prefix + wantMajor
	if !pc.ModuleExists(fixed) {
		return false // attempted fixed module doesn't exist, give up
	}
	m.Module = fixed
	return true
}

const (
	v0   = "v0"
	v1   = "v1"
	v0v1 = "v0 or v1"
)

func major(v string) string {
	m := version.Major(v)
	if m == v0 || m == v1 {
		return v0v1
	}
	return m
}

// commonMajor returns the major version path suffix (e.g. "/v2") common
// to all versions in the version range, or ("", false) if not all versions
// have the same major version.
// Returns ("", true) if the major version is 0 or 1.
func commonMajor(vs []report.VersionRange) (_ string, ok bool) {
	maj := major(first(vs))
	for _, vr := range vs {
		for _, v := range []string{vr.Introduced, vr.Fixed} {
			if v == "" {
				continue
			}
			current := major(v)
			if current != maj {
				return "", false
			}
		}
	}
	if maj == v0v1 {
		return "", true
	}
	return "/" + maj, true
}

// canonicalize attempts to canonicalize the module path,
// and updates the module path and packages list if successful.
// Modifies m.
//
// Does nothing if the module path is already canonical, or isn't recognized
// by the proxy at all.
func canonicalize(m *report.Module, pc *proxy.Client) {
	if len(m.Versions) == 0 {
		return // no versions, don't attempt to fix
	}

	canonical, err := commonCanonical(m, pc)
	if err != nil {
		return // no consistent canonical version found, don't attempt to fix
	}

	original := m.Module
	m.Module = canonical

	// Fix any package paths.
	for _, p := range m.Packages {
		if strings.HasPrefix(p.Package, original) {
			p.Package = canonical + strings.TrimPrefix(p.Package, original)
		}
	}
}

func commonCanonical(m *report.Module, pc *proxy.Client) (string, error) {
	canonical, err := pc.CanonicalModulePath(m.Module, first(m.Versions))
	if err != nil {
		return "", err
	}

	for _, vr := range m.Versions {
		for _, v := range []string{vr.Introduced, vr.Fixed} {
			if v == "" {
				continue
			}
			current, err := pc.CanonicalModulePath(m.Module, v)
			if err != nil {
				return "", err
			}
			if current != canonical {
				return "", fmt.Errorf("inconsistent canonical module paths: %s and %s", canonical, current)
			}
		}
	}
	return canonical, nil
}

// addIncompatible adds "+incompatible" to all versions where module@version
// does not exist but module@version+incompatible does exist.
// TODO(https://go.dev/issue/61769): Consider making this work for
// non-canonical versions too (example: GHSA-w4xh-w33p-4v29).
func addIncompatible(m *report.Module, pc *proxy.Client) {
	tryAdd := func(v string) (string, bool) {
		if v == "" {
			return "", false
		}
		if major(v) == v0v1 {
			return "", false // +incompatible does not apply for major versions < 2
		}
		if pc.ModuleExistsAtTaggedVersion(m.Module, v) {
			return "", false // module@version is already OK
		}
		if vi := v + "+incompatible"; pc.ModuleExistsAtTaggedVersion(m.Module, vi) {
			return vi, true
		}
		return "", false // module@version+incompatible doesn't exist
	}
	for i, vr := range m.Versions {
		if vi, ok := tryAdd(vr.Introduced); ok {
			m.Versions[i].Introduced = vi
		}
		if vi, ok := tryAdd(vr.Fixed); ok {
			m.Versions[i].Fixed = vi
		}
	}
}

func sortModules(ms []*report.Module) {
	sort.SliceStable(ms, func(i, j int) bool {
		m1, m2 := ms[i], ms[j]
		// Break ties by lowest affected version, assuming the version list is sorted.
		if m1.Module == m2.Module {
			vr1, vr2 := m1.Versions, m2.Versions
			if len(vr1) == 0 {
				return true
			} else if len(vr2) == 0 {
				return false
			}

			v1, v2 := first(vr1), first(vr2)
			if v1 == v2 {
				pkgs1, pkgs2 := m1.Packages, m2.Packages
				if len(pkgs1) == 0 {
					return true
				} else if len(pkgs2) == 0 {
					return false
				}
				return pkgs1[0].Package < pkgs2[0].Package
			}

			return version.Before(v1, v2)
		}
		return m1.Module < m2.Module
	})
}

// merge merges all modules with the same module & package info
// (but possibly different versions) into one.
func merge(ms []*report.Module) []*report.Module {
	type compMod struct {
		path     string
		packages string // sorted, comma separated list of package names
	}

	toCompMod := func(m *report.Module) compMod {
		var packages []string
		for _, p := range m.Packages {
			packages = append(packages, p.Package)
		}
		return compMod{
			path:     m.Module,
			packages: strings.Join(packages, ","),
		}
	}

	merge := func(m1, m2 *report.Module) *report.Module {
		// only run if m1 and m2 are same except versions
		// deletes vulnerable_at if set
		return &report.Module{
			Module:              m1.Module,
			Versions:            append(m1.Versions, m2.Versions...),
			UnsupportedVersions: append(m1.UnsupportedVersions, m2.UnsupportedVersions...),
			Packages:            m1.Packages,
		}
	}

	modules := make(map[compMod]*report.Module)
	for _, m := range ms {
		c := toCompMod(m)
		mod, ok := modules[c]
		if !ok {
			modules[c] = m
		} else {
			modules[c] = merge(mod, m)
		}
	}

	return maps.Values(modules)
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

func convertVersions(rs []osvschema.Range) ([]report.VersionRange, []report.UnsupportedVersion) {
	var vrs []report.VersionRange
	var uvs []report.UnsupportedVersion
	for _, r := range rs {
		for _, e := range r.Events {
			if e.Introduced != "" || e.Fixed != "" {
				var vr report.VersionRange
				switch {
				case e.Introduced == "0":
					continue
				case e.Introduced != "":
					vr.Introduced = e.Introduced
				case e.Fixed != "":
					vr.Fixed = e.Fixed
				}
				vrs = append(vrs, vr)
				continue
			}

			var uv report.UnsupportedVersion
			switch {
			case e.LastAffected != "":
				uv.Version = e.LastAffected
				uv.Type = "last_affected"
			case e.Limit != "":
				uv.Version = e.Limit
				uv.Type = "limit"
			default:
				uv.Version = fmt.Sprint(e)
				uv.Type = "unknown"
			}
			uvs = append(uvs, uv)
		}
	}
	return vrs, uvs
}

var (
	goAdvisory = regexp.MustCompile(`^https://pkg.go.dev/vuln/.*$`)
)

func convertRef(ref osvschema.Reference) *report.Reference {
	return &report.Reference{
		Type: osv.ReferenceType(ref.Type),
		URL:  ref.URL,
	}
}

// fixRefs deletes some unneeded references, and attempts to fix reference types.
// Modifies r.
//
// Deletes:
//   - "package"-type references
//   - Go advisory references (these are redundant for us)
//
// Changes:
//   - reference type to "advisory" for GHSA and CVE links.
//   - reference type to "fix" for Github pull requests and commit links in one of
//     the affected modules
//   - reference type to "report" for Github issues in one of
//     the affected modules
func fixRefs(r *report.Report) {
	r.References = slices.DeleteFunc(r.References, func(ref *report.Reference) bool {
		return ref.Type == osv.ReferenceTypePackage ||
			goAdvisory.MatchString(ref.URL)
	})

	if len(r.References) == 0 {
		r.References = nil
		return
	}

	oneOfRE := func(s []string) string {
		return `(` + strings.Join(s, "|") + `)`
	}

	ghsaAdvisory := regexp.MustCompile(`^https://github.com/.*advisories/(` + oneOfRE(r.GHSAs) + `)$`)
	cveAdvisory := regexp.MustCompile(`^https://nvd.nist.gov/vuln/detail/(` + oneOfRE(r.CVEs) + `)$`)

	// For now, this will not attempt to fix reference types for
	// modules whose canonical names are different from their github path.
	var modulePaths []string
	for _, m := range r.Modules {
		modulePaths = append(modulePaths, m.Module)
	}
	moduleRE := oneOfRE(modulePaths)
	issue := regexp.MustCompile(`https://` + moduleRE + `/issue(s?)/.*$`)
	fix := regexp.MustCompile(`https://` + moduleRE + `/(commit(s?)|pull)/.*$`)

	for _, ref := range r.References {
		switch {
		case ghsaAdvisory.MatchString(ref.URL) ||
			cveAdvisory.MatchString(ref.URL):
			ref.Type = osv.ReferenceTypeAdvisory
		case issue.MatchString(ref.URL):
			ref.Type = osv.ReferenceTypeReport
		case fix.MatchString(ref.URL):
			ref.Type = osv.ReferenceTypeFix
		}
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
