// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/mod/module"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/version"
)

func (r *Report) Fix(pc *proxy.Client) {
	expandGitCommits(r)
	r.FixModules(pc)
	r.FixText()
	r.FixReferences()
}

func (r *Report) FixText() {
	fixLines := func(sp *string) {
		*sp = fixLineLength(*sp, maxLineLength)
	}
	fixLines((*string)(&r.Summary))
	fixLines((*string)(&r.Description))
	if r.CVEMetadata != nil {
		fixLines(&r.CVEMetadata.Description)
	}

	r.fixSummary()
}

func (r *Report) fixSummary() {
	summary := r.Summary.String()

	// If there is no summary, create a basic one.
	if summary == "" {
		if aliases := r.Aliases(); len(aliases) != 0 {
			summary = aliases[0]
		} else {
			summary = "Vulnerability"
		}
	}

	// Add a path if one exists and is needed.
	if paths := r.nonStdPaths(); len(paths) > 0 && !containsPath(summary, paths) {
		summary = fmt.Sprintf("%s in %s", summary, paths[0])
	}

	r.Summary = Summary(summary)
}

// FixVersions replaces each version with its canonical form (if possible),
// sorts version ranges, and collects version ranges into a compact form.
func (m *Module) FixVersions(pc *proxy.Client) {
	fixVersion := func(v string) string {
		if v == "" {
			return ""
		}
		if version.IsCommitHash(v) {
			if c, err := pc.CanonicalModuleVersion(m.Module, v); err == nil { // no error
				v = c
			}
		}
		v = version.TrimPrefix(v)
		if version.IsValid(v) {
			v = version.Canonical(v)
		}
		return v
	}

	for i, vr := range m.Versions {
		m.Versions[i].Introduced = fixVersion(vr.Introduced)
		m.Versions[i].Fixed = fixVersion(vr.Fixed)
	}
	m.VulnerableAt = fixVersion(m.VulnerableAt)

	sort.SliceStable(m.Versions, func(i, j int) bool {
		intro, fixed := m.Versions[i].Introduced, m.Versions[i].Fixed
		intro2, fixed2 := m.Versions[j].Introduced, m.Versions[j].Fixed
		switch {
		case intro != "" && intro2 != "":
			return version.Before(intro, intro2)
		case intro != "" && fixed2 != "":
			return version.Before(intro, fixed2)
		case fixed != "" && intro2 != "":
			return version.Before(fixed, intro2)
		case fixed != "" && fixed2 != "":
			return version.Before(fixed, fixed2)
		default:
			return false
		}
	})

	// Remove duplicate version ranges.
	m.Versions = slices.Compact(m.Versions)

	// Collect together version ranges that don't need to be separate,
	// e.g:
	// [ {Introduced: 1.1.0}, {Fixed: 1.2.0} ] becomes
	// [ {Introduced: 1.1.0, Fixed: 1.2.0} ].
	for i := 0; i < len(m.Versions); i++ {
		if i != 0 {
			current, prev := m.Versions[i], m.Versions[i-1]
			if (prev.Introduced != "" && prev.Fixed == "") &&
				(current.Introduced == "" && current.Fixed != "") {
				m.Versions[i-1].Fixed = current.Fixed
				m.Versions = append(m.Versions[:i], m.Versions[i+1:]...)
				i--
			}
		}
	}

	m.fixVulnerableAt(pc)
}

func (m *Module) fixVulnerableAt(pc *proxy.Client) {
	if m.VulnerableAt != "" {
		return
	}
	// Don't attempt to guess if the given version ranges don't make sense.
	if err := m.checkModVersions(pc); err != nil {
		return
	}
	v, err := m.guessVulnerableAt(pc)
	if err != nil {
		return
	}
	m.VulnerableAt = v
}

// guessVulnerableAt attempts to find a vulnerable_at
// version using the module proxy, assuming that the version ranges
// have already been validated.
// If there is no fix, the latest version is used.
func (m *Module) guessVulnerableAt(pc *proxy.Client) (v string, err error) {
	if m.IsFirstParty() {
		return "", errors.New("cannot auto-guess vulnerable_at for first-party modules")
	}

	// Find the last fixed version, assuming the version ranges are sorted.
	fixed := ""
	if len(m.Versions) > 0 {
		fixed = m.Versions[len(m.Versions)-1].Fixed
	}

	// If there is no fix, find the latest version of the module.
	if fixed == "" {
		latest, err := pc.Latest(m.Module)
		if err != nil || latest == "" {
			return "", fmt.Errorf("no fix, but could not find latest version from proxy: %s", err)
		}

		return latest, nil
	}

	// If the latest fixed version is a 0.0.0 pseudo-version, or not a valid version,
	// don't attempt to determine the vulnerable_at version.
	if !version.IsValid(fixed) {
		return "", errors.New("cannot auto-guess when fixed version is invalid")
	}
	if strings.HasPrefix(fixed, "0.0.0-") {
		return "", errors.New("cannot auto-guess when fixed version is 0.0.0 pseudo-version")
	}

	// Otherwise, find the version right before the fixed version.
	vs, err := pc.Versions(m.Module)
	if err != nil {
		return "", fmt.Errorf("could not find versions from proxy: %s", err)
	}
	for i := len(vs) - 1; i >= 0; i-- {
		if version.Before(vs[i], fixed) {
			return vs[i], nil
		}
	}

	return "", errors.New("could not find tagged version less than fixed")
}

// fixLineLength returns a copy of s with all lines trimmed to <=n characters
// (with the exception of single-word lines).
// It preserves paragraph breaks (indicated by "\n\n") and markdown-style list
// breaks.
func fixLineLength(s string, n int) string {
	var result strings.Builder
	result.Grow(len(s))
	for i, paragraph := range strings.Split(toParagraphs(s), "\n\n") {
		if i > 0 {
			result.WriteString("\n\n")
		}
		var lines []string
		for _, forcedLine := range strings.Split(paragraph, "\n") {
			words := strings.Split(forcedLine, " ")
			start, length := 0, 0
			for k, word := range words {
				newLength := length + len(word)
				if length > 0 {
					newLength++ // space character
				}
				if newLength <= n {
					length = newLength
					continue
				}
				// Adding the word would put the line over the max length,
				// so add the line as is (if it is non-empty).
				if length > 0 {
					lines = append(lines, strings.Join(words[start:k], " "))
				}
				// Begin a new line with just the word.
				start, length = k, len(word)
			}
			// Add the last line.
			if length > 0 {
				lines = append(lines, strings.Join(words[start:], " "))
			}
		}
		result.WriteString(strings.Join(lines, "\n"))
	}
	return result.String()
}

var urlReplacements = []struct {
	re   *regexp.Regexp
	repl string
}{{
	regexp.MustCompile(`golang.org`),
	`go.dev`,
}, {
	regexp.MustCompile(`https?://groups.google.com/forum/\#\![^/]*/([^/]+)/([^/]+)/(.*)`),

	`https://groups.google.com/g/$1/c/$2/m/$3`,
}, {
	regexp.MustCompile(`.*github.com/golang/go/issues`),
	`https://go.dev/issue`,
}, {
	regexp.MustCompile(`.*github.com/golang/go/commit`),
	`https://go.googlesource.com/+`,
},
}

func fixURL(u string) string {
	for _, repl := range urlReplacements {
		u = repl.re.ReplaceAllString(u, repl.repl)
	}
	return u
}

func (r *Report) FixModules(pc *proxy.Client) {
	for _, m := range r.Modules {
		extractImportPath(m, pc)
		if ok := fixMajorVersion(m, pc); !ok {
			addIncompatible(m, pc)
		}
		canonicalize(m, pc)
	}

	r.Modules = merge(r.Modules)

	// Fix the versions *after* the modules have been merged.
	for _, m := range r.Modules {
		m.FixVersions(pc)
	}

	sortModules(r.Modules)
}

// extractImportPath checks if the module m's "module" path is actually
// an import path. If so, it adds the import path to the packages list
// and fixes the module path. Modifies m.
//
// Does nothing if the module path is already correct, or isn't recognized
// by the proxy at all.
func extractImportPath(m *Module, pc *proxy.Client) {
	path := m.Module
	modulePath, err := pc.FindModule(m.Module)
	if err != nil || // path doesn't contain a module, needs human review
		path == modulePath { // path is already a module, no action needed
		return
	}
	m.Module = modulePath
	m.Packages = append(m.Packages, &Package{Package: path})
}

// fixMajorVersion corrects the major version prefix of the module
// path if possible.
// Returns true if the major version was already correct or could be
// fixed.
// For now, it gives up if it encounters various problems and
// special cases (see comments inline).
func fixMajorVersion(m *Module, pc *proxy.Client) (ok bool) {
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
	hasIntroduced := func(m *Module) bool {
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
func commonMajor(vs []VersionRange) (_ string, ok bool) {
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
func canonicalize(m *Module, pc *proxy.Client) {
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

func commonCanonical(m *Module, pc *proxy.Client) (string, error) {
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
func addIncompatible(m *Module, pc *proxy.Client) {
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

func sortModules(ms []*Module) {
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
func merge(ms []*Module) []*Module {
	type compMod struct {
		path     string
		packages string // sorted, comma separated list of package names
	}

	toCompMod := func(m *Module) compMod {
		var packages []string
		for _, p := range m.Packages {
			packages = append(packages, p.Package)
		}
		return compMod{
			path:     m.Module,
			packages: strings.Join(packages, ","),
		}
	}

	merge := func(m1, m2 *Module) *Module {
		// only run if m1 and m2 are same except versions
		// deletes vulnerable_at if set
		return &Module{
			Module:              m1.Module,
			Versions:            append(m1.Versions, m2.Versions...),
			UnsupportedVersions: append(m1.UnsupportedVersions, m2.UnsupportedVersions...),
			Packages:            m1.Packages,
		}
	}

	modules := make(map[compMod]*Module)
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

func first(vrs []VersionRange) string {
	for _, vr := range vrs {
		for _, v := range []string{vr.Introduced, vr.Fixed} {
			if v != "" {
				return v
			}
		}
	}
	return ""
}

var (
	goAdvisory = regexp.MustCompile(`^https://pkg.go.dev/vuln/.*$`)
)

// FixReferences deletes some unneeded references, and attempts to fix reference types.
// Modifies r.
//
// Deletes:
//   - "package"-type references
//   - Go advisory references (these are redundant for us)
//   - all advisories except the "best" one (if applicable)
//
// Changes:
//   - reference type to "advisory" for GHSA and CVE links.
//   - reference type to "fix" for Github pull requests and commit links in one of
//     the affected modules
//   - reference type to "report" for Github issues in one of
//     the affected modules
func (r *Report) FixReferences() {
	for _, ref := range r.References {
		ref.URL = fixURL(ref.URL)
	}

	re := newRE(r)

	for _, ref := range r.References {
		switch re.Type(ref.URL) {
		case urlTypeAdvisory:
			ref.Type = osv.ReferenceTypeAdvisory
		case urlTypeIssue:
			ref.Type = osv.ReferenceTypeReport
		case urlTypeFix:
			ref.Type = osv.ReferenceTypeFix
		}
	}

	bestAdvisory, found := re.bestAdvisory(r.References)
	isUnnecessaryAdvisory := func(ref *Reference) bool {
		return found && ref.Type == osv.ReferenceTypeAdvisory && ref.URL != bestAdvisory
	}

	r.References = slices.DeleteFunc(r.References, func(ref *Reference) bool {
		return ref.Type == osv.ReferenceTypePackage ||
			goAdvisory.MatchString(ref.URL) ||
			isUnnecessaryAdvisory(ref)
	})

	if r.missingAdvisory(r.countAdvisories()) {
		r.addAdvisory()
	}

	if len(r.References) == 0 {
		r.References = nil
	}
}

func (r *Report) addAdvisory() {
	// For now, only add an advisory if there is a CVE.
	if len(r.CVEs) > 0 {
		r.References = append(r.References, &Reference{
			Type: osv.ReferenceTypeAdvisory,
			URL:  fmt.Sprintf("%s%s", NISTPrefix, r.CVEs[0]),
		})
	}
}

// bestAdvisory returns the URL of the "best" advisory in the references,
// or ("", false) if none can be found.
// Repository-level GHSAs are considered the best, followed by regular
// GHSAs, followed by CVEs.
// For now, if there are advisories mentioning two or more
// aliases of the same type, we don't try to determine which is best.
// (For example, if there are two advisories, referencing GHSA-1 and GHSA-2, we leave it
// to the triager to pick the best one.)
func (re *reportRE) bestAdvisory(refs []*Reference) (string, bool) {
	bestAdvisory := ""
	bestType := advisoryTypeUnknown
	ghsas, cves := make(map[string]bool), make(map[string]bool)
	for _, ref := range refs {
		if ref.Type != osv.ReferenceTypeAdvisory {
			continue
		}
		t, alias := re.AdvisoryType(ref.URL)
		if t > bestType {
			bestAdvisory = ref.URL
			bestType = t
		}

		if ghsa.IsGHSA(alias) {
			ghsas[alias] = true
		} else if cveschema5.IsCVE(alias) {
			cves[alias] = true
		}
	}

	if len(ghsas) > 1 || len(cves) > 1 {
		return "", false
	}

	return bestAdvisory, bestAdvisory != ""
}

type urlType int

const (
	urlTypeUnknown urlType = iota
	urlTypeIssue
	urlTypeFix
	urlTypeAdvisory
)

func (re *reportRE) Type(url string) urlType {
	switch {
	case re.ghsa.MatchString(url):
		return urlTypeAdvisory
	case re.ghsaRepo.MatchString(url):
		return urlTypeAdvisory
	case re.cve.MatchString(url):
		return urlTypeAdvisory
	case re.issue.MatchString(url):
		return urlTypeIssue
	case re.fix.MatchString(url):
		return urlTypeFix
	}
	return urlTypeUnknown
}

type advisoryType int

// Advisory link types in ascending order of (likely) quality.
// In general, repo-level GHSAs tend to be the best because
// they are more likely to be directly created by a maintainer.
const (
	advisoryTypeUnknown advisoryType = iota
	advisoryTypeCVE
	advisoryTypeGHSA
	advisoryTypeGHSARepo
)

func (re *reportRE) AdvisoryType(url string) (t advisoryType, alias string) {
	if m := re.ghsa.FindStringSubmatch(url); len(m) == 2 {
		return advisoryTypeGHSA, m[1]
	}

	if m := re.ghsaRepo.FindStringSubmatch(url); len(m) == 2 {
		return advisoryTypeGHSARepo, m[1]
	}

	if m := re.cve.FindStringSubmatch(url); len(m) == 2 {
		return advisoryTypeCVE, m[1]
	}

	return advisoryTypeUnknown, ""
}

type reportRE struct {
	ghsa, ghsaRepo, cve, issue, fix *regexp.Regexp
}

func newRE(r *Report) *reportRE {
	oneOfRE := func(s []string) string {
		return `(` + strings.Join(s, "|") + `)`
	}

	// For now, this will not attempt to fix reference types for
	// modules whose canonical names are different from their github path.
	var modulePaths []string
	for _, m := range r.Modules {
		modulePaths = append(modulePaths, m.Module)
	}
	moduleRE := oneOfRE(modulePaths)

	return &reportRE{
		ghsa:     regexp.MustCompile(`^https://github.com/advisories/` + oneOfRE(r.GHSAs) + `$`),
		ghsaRepo: regexp.MustCompile(`^https://github.com/.+/advisories/` + oneOfRE(r.GHSAs) + `$`),
		cve:      regexp.MustCompile(`^https://nvd.nist.gov/vuln/detail/` + oneOfRE(r.CVEs) + `$`),
		issue:    regexp.MustCompile(`https://` + moduleRE + `/issue(s?)/.*$`),
		fix:      regexp.MustCompile(`https://` + moduleRE + `/(commit(s?)|pull)/.*$`),
	}
}
