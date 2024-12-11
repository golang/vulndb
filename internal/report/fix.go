// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/mod/module"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/version"
)

func (r *Report) Fix(pc *proxy.Client) {
	r.deleteNotes(NoteTypeFix)
	expandGitCommits(r)
	_ = r.FixModules(pc)
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
		summary = fmt.Sprintf("%s in %s", summary, stripMajor(paths[0]))
	}

	r.Summary = Summary(fixSpelling(summary))
}

func stripMajor(path string) string {
	base, _, ok := module.SplitPathVersion(path)
	if !ok {
		return path
	}
	return base
}

func (v *Version) commitHashToVersion(modulePath string, pc *proxy.Client) {
	if v == nil {
		return
	}

	vv := v.Version
	if version.IsCommitHash(vv) {
		if c, err := pc.CanonicalModuleVersion(modulePath, vv); err == nil { // no error
			v.Version = c
		}
	}
}

// FixVersions replaces each version with its canonical form (if possible),
// sorts version ranges, and moves versions to their proper spot.
func (m *Module) FixVersions(pc *proxy.Client) {
	for _, v := range m.Versions {
		v.commitHashToVersion(m.Module, pc)
	}
	m.VulnerableAt.commitHashToVersion(m.Module, pc)

	m.Versions.fix()
	m.UnsupportedVersions.fix()
	m.VulnerableAt.fix()

	if pc != nil && !m.IsFirstParty() {
		found, notFound, _ := m.classifyVersions(pc)
		if len(notFound) != 0 {
			m.Versions = found
			m.NonGoVersions = append(m.NonGoVersions, notFound...)
		}
	}
}

func (v *Version) fix() {
	if v == nil {
		return
	}
	vv := version.TrimPrefix(v.Version)
	if version.IsValid(vv) {
		vv = version.Canonical(vv)
	}
	v.Version = vv
}

func (vs *Versions) fix() {
	for i := range *vs {
		(*vs)[i].fix()
	}
	sort.SliceStable(*vs, func(i, j int) bool {
		return version.Before((*vs)[i].Version, (*vs)[j].Version)
	})
	// Remove duplicates.
	*vs = slices.Compact(*vs)
	*vs = slices.CompactFunc(*vs, func(a, b *Version) bool {
		return a.Type == b.Type && a.Version == b.Version
	})
}

func (m *Module) fixVulnerableAt(pc *proxy.Client) error {
	if m.VulnerableAt != nil {
		return nil
	}
	if m.IsFirstParty() {
		return fmt.Errorf("not implemented for std/cmd")
	}
	// Don't attempt to guess if the given version ranges don't make sense.
	if err := m.checkModVersions(pc); err != nil {
		return err
	}
	v, err := m.guessVulnerableAt(pc)
	if err != nil {
		return err
	}
	m.VulnerableAt = VulnerableAt(v)
	return nil
}

var errZeroPseudo = errors.New("cannot auto-guess when fixed version is 0.0.0 pseudo-version")

// Find the latest fixed and introduced version, assuming the version
// ranges are sorted and valid.
func (vs Versions) latestVersions() (introduced, fixed *Version) {
	if len(vs) == 0 {
		return
	}
	last := vs[len(vs)-1]
	if last.IsIntroduced() {
		introduced = last
		return
	}
	fixed = last
	if len(vs) > 1 {
		if penultimate := vs[len(vs)-2]; penultimate.IsIntroduced() {
			introduced = penultimate
		}
	}
	return
}

// guessVulnerableAt attempts to find a vulnerable_at
// version using the module proxy, assuming that the version ranges
// have already been validated.
// If there is no fix, the latest version is used.
func (m *Module) guessVulnerableAt(pc *proxy.Client) (v string, err error) {
	if m.IsFirstParty() {
		return "", errors.New("cannot auto-guess vulnerable_at for first-party modules")
	}

	introduced, fixed := m.Versions.latestVersions()

	// If there is no latest fix, find the latest version of the module.
	if fixed == nil {
		latest, err := pc.Latest(m.Module)
		if err != nil || latest == "" {
			return "", fmt.Errorf("no fix, but could not find latest version from proxy: %s", err)
		}
		if introduced != nil && version.Before(latest, introduced.Version) {
			return "", fmt.Errorf("latest version (%s) is before last introduced version", latest)
		}
		return latest, nil
	}

	// If the latest fixed version is a 0.0.0 pseudo-version, or not a valid version,
	// don't attempt to determine the vulnerable_at version.
	if !version.IsValid(fixed.Version) {
		return "", errors.New("cannot auto-guess when fixed version is invalid")
	}
	if strings.HasPrefix(fixed.Version, "0.0.0-") {
		return "", errZeroPseudo
	}

	// Otherwise, find the version right before the fixed version.
	vs, err := pc.Versions(m.Module)
	if err != nil {
		return "", fmt.Errorf("could not find versions from proxy: %s", err)
	}
	for i := len(vs) - 1; i >= 0; i-- {
		if version.Before(vs[i], fixed.Version) {
			// Make sure the version is >= the latest introduced version.
			if introduced == nil || !version.Before(vs[i], introduced.Version) {
				return vs[i], nil
			}
		}
	}

	return "", errors.New("could not find tagged version between introduced and fixed")
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

func (r *Report) FixModules(pc *proxy.Client) (errs error) {
	var fixed []*Module
	for _, m := range r.Modules {
		m.VulnerableAt.commitHashToVersion(m.Module, pc)
		m.Module = transform(m.Module)
		extractImportPath(m, pc)
		fixed = append(fixed, m.splitByMajor(pc)...)
	}
	r.Modules = fixed

	merged, err := merge(fixed)
	if err != nil {
		r.AddNote(NoteTypeFix, "module merge error: %s", err)
		errs = errors.Join(errs, err)
	} else {
		r.Modules = merged
	}

	// For non-reviewed reports, assume that all major versions
	// up to the highest mentioned are affected at all versions.
	if !r.IsReviewed() {
		r.addMissingMajors(pc)
	}

	// Fix the versions *after* the modules have been merged.
	for _, m := range r.Modules {
		m.FixVersions(pc)
		if err := m.fixVulnerableAt(pc); err != nil {
			r.AddNote(NoteTypeFix, "%s: could not add vulnerable_at: %v", m.Module, err)
			errs = errors.Join(errs, err)
		}
	}

	sortModules(r.Modules)
	return errs
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

func (m *Module) hasVersions() bool {
	return len(m.Versions) != 0 || len(m.NonGoVersions) != 0 || len(m.UnsupportedVersions) != 0
}

type majorInfo struct {
	base string
	high int
	all  map[int]bool
}

func majorToInt(maj string) (int, bool) {
	if maj == "" {
		return 0, true
	}
	i, err := strconv.Atoi(strings.TrimPrefix(maj, "/v"))
	if err != nil {
		return 0, false
	}
	return i, true
}

func intToMajor(i int) string {
	if i == 0 {
		return v0v1
	}
	return fmt.Sprintf("v%d", i)
}

func (r *Report) addMissingMajors(pc *proxy.Client) {
	// Map from module v1 path to set of all listed major versions.
	majorMap := make(map[string]*majorInfo)
	for _, m := range r.Modules {
		base, pathMajor, ok := module.SplitPathVersion(m.Module)
		if !ok { // couldn't parse module path, skip
			continue
		}
		i, ok := majorToInt(pathMajor)
		if !ok { // invalid major version, skip
			continue
		}
		v1Mod := modulePath(base, v0v1)
		if majorMap[v1Mod] == nil {
			majorMap[v1Mod] = &majorInfo{
				base: base,
				all:  make(map[int]bool),
			}
		}
		if i > majorMap[v1Mod].high {
			majorMap[v1Mod].high = i
		}
		majorMap[v1Mod].all[i] = true
	}

	for _, mi := range majorMap {
		for i := 0; i < mi.high; i++ {
			if mi.all[i] {
				continue
			}
			mod := modulePath(mi.base, intToMajor(i))
			if !pc.ModuleExists(mod) {
				continue
			}
			r.Modules = append(r.Modules, &Module{
				Module: mod,
			})
		}
	}
}

func (m *Module) splitByMajor(pc *proxy.Client) (modules []*Module) {
	if stdlib.IsCmdModule(m.Module) || stdlib.IsStdModule(m.Module) || // no major versions for stdlib
		!m.hasVersions() || // no versions -> no need to split
		strings.HasPrefix(m.Module, "gopkg.in/") { // for now, don't attempt to split gopkg.in modules
		return []*Module{m}
	}

	base, _, ok := module.SplitPathVersion(m.Module)
	if !ok { // couldn't parse module path, don't attempt to fix
		return []*Module{m}
	}
	v1Mod := modulePath(base, v0v1)
	rawMajorMap := m.byMajor()
	validated := make(map[string]*allVersions)

	for maj, av := range rawMajorMap {
		mod := modulePath(base, maj)
		// If the module at the major version doesn't exist, add the
		// version to the v1 module.
		if mod == v1Mod || !pc.ModuleExists(mod) {
			if validated[v1Mod] == nil {
				validated[v1Mod] = new(allVersions)
			}
			validated[v1Mod].add(av)
			continue
		}
		validated[mod] = av
	}

	// Ensure that the original module mentioned is preserved,
	// if it exists, even if there are now no versions associated
	// with it.
	original := m.Module
	if _, ok := validated[original]; !ok {
		if pc.ModuleExists(original) {
			validated[original] = &allVersions{}
		}
	}

	for mod, av := range validated {
		mc := m.copy()
		mc.Module = mod
		mc.Versions = av.standard
		mc.UnsupportedVersions = av.unsupported
		mc.NonGoVersions = av.nonGo
		if !inVulnerableRange(mc.Versions, mc.VulnerableAt) {
			mc.VulnerableAt = nil // needs to be re-generated
		}
		if mod == v1Mod {
			addIncompatible(mc, pc)
		}
		canonicalize(mc, pc)
		modules = append(modules, mc)
	}

	return modules
}

func inVulnerableRange(vs Versions, v *Version) bool {
	if v == nil {
		return false
	}

	rs, err := vs.ToSemverRanges()
	if err != nil {
		return false
	}
	affected, err := osvutils.AffectsSemver(rs, v.Version)
	if err != nil {
		return false
	}

	return affected
}

var transforms = map[string]string{
	"github.com/mattermost/mattermost/server":    "github.com/mattermost/mattermost-server",
	"github.com/mattermost/mattermost/server/v5": "github.com/mattermost/mattermost-server/v5",
	"github.com/mattermost/mattermost/server/v6": "github.com/mattermost/mattermost-server/v6",
}

func transform(m string) string {
	if t, ok := transforms[m]; ok {
		return t
	}
	return m
}

func modulePath(prefix, pathMajor string) string {
	raw := func(prefix, pathMajor string) string {
		if pathMajor == v0v1 {
			return prefix
		}
		return prefix + "/" + pathMajor
	}
	return transform(raw(prefix, pathMajor))
}

func (m *Module) copy() *Module {
	return &Module{
		Module:               m.Module,
		Versions:             m.Versions.copy(),
		NonGoVersions:        m.NonGoVersions.copy(),
		UnsupportedVersions:  m.UnsupportedVersions.copy(),
		VulnerableAt:         m.VulnerableAt.copy(),
		VulnerableAtRequires: slices.Clone(m.VulnerableAtRequires),
		Packages:             copyPackages(m.Packages),
		FixLinks:             slices.Clone(m.FixLinks),
	}
}

func (vs Versions) copy() Versions {
	if vs == nil {
		return nil
	}
	vsc := make(Versions, len(vs))
	for i, v := range vs {
		vsc[i] = v.copy()
	}
	return vsc
}

func (v *Version) copy() *Version {
	if v == nil {
		return nil
	}
	return &Version{
		Type:    v.Type,
		Version: v.Version,
	}
}

func copyPackages(ps []*Package) []*Package {
	if ps == nil {
		return nil
	}
	psc := make([]*Package, len(ps))
	for i, p := range ps {
		psc[i] = p.copy()
	}
	return psc
}

func (p *Package) copy() *Package {
	if p == nil {
		return nil
	}
	return &Package{
		Package:         p.Package,
		GOOS:            slices.Clone(p.GOOS),
		GOARCH:          slices.Clone(p.GOARCH),
		Symbols:         slices.Clone(p.Symbols),
		DerivedSymbols:  slices.Clone(p.DerivedSymbols),
		ExcludedSymbols: slices.Clone(p.ExcludedSymbols),
		SkipFixSymbols:  p.SkipFixSymbols,
	}
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

type allVersions struct {
	standard, unsupported, nonGo Versions
}

func (a *allVersions) add(b *allVersions) {
	if b == nil {
		return
	}
	a.standard = append(a.standard, b.standard...)
	a.unsupported = append(a.unsupported, b.unsupported...)
	a.nonGo = append(a.nonGo, b.nonGo...)
}

func (m *Module) byMajor() map[string]*allVersions {
	mp := make(map[string]*allVersions)
	getMajor := func(v *Version) string {
		maj := major(v.Version)
		if mp[maj] == nil {
			mp[maj] = new(allVersions)
		}
		return maj
	}
	for _, v := range m.Versions {
		maj := getMajor(v)
		mp[maj].standard = append(mp[maj].standard, v)
	}
	for _, v := range m.UnsupportedVersions {
		maj := getMajor(v)
		mp[maj].unsupported = append(mp[maj].unsupported, v)
	}
	for _, v := range m.NonGoVersions {
		maj := getMajor(v)
		mp[maj].nonGo = append(mp[maj].nonGo, v)
	}
	return mp
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
	if len(m.Versions) == 0 {
		return m.Module, nil
	}

	canonical, err := pc.CanonicalModulePath(m.Module, m.Versions[0].Version)
	if err != nil {
		return "", err
	}

	for _, v := range m.Versions {
		current, err := pc.CanonicalModulePath(m.Module, v.Version)
		if err != nil {
			return "", err
		}
		if current != canonical {
			return "", fmt.Errorf("inconsistent canonical module paths: %s and %s", canonical, current)
		}
	}
	return canonical, nil
}

// addIncompatible adds "+incompatible" to all versions where module@version
// does not exist but module@version+incompatible does exist.
// TODO(https://go.dev/issue/61769): Consider making this work for
// non-canonical versions too (example: GHSA-w4xh-w33p-4v29).
func addIncompatible(m *Module, pc *proxy.Client) {
	tryAdd := func(v string) string {
		if v == "" {
			return v
		}
		if major(v) == v0v1 {
			return v // +incompatible does not apply for major versions < 2
		}
		if pc.ModuleExistsAtTaggedVersion(m.Module, v) {
			return v // module@version is already OK
		}
		if vi := v + "+incompatible"; pc.ModuleExistsAtTaggedVersion(m.Module, vi) {
			return vi
		}
		return v // module@version+incompatible doesn't exist
	}
	for i, v := range m.Versions {
		m.Versions[i].Version = tryAdd(v.Version)
	}
}

func sortModules(ms []*Module) {
	sort.SliceStable(ms, func(i, j int) bool {
		m1, m2 := ms[i], ms[j]

		// Break ties by versions, assuming the version list is sorted.
		// If needed, further break ties by packages.
		if m1.Module == m2.Module {
			byPackage := func(m1, m2 *Module) bool {
				pkgs1, pkgs2 := m1.Packages, m2.Packages
				if len(pkgs1) == 0 {
					return true
				} else if len(pkgs2) == 0 {
					return false
				}
				return pkgs1[0].Package < pkgs2[0].Package
			}

			vr1, vr2 := m1.Versions, m2.Versions
			if len(vr1) == 0 && len(vr2) == 0 {
				return byPackage(m1, m2)
			} else if len(vr1) == 0 {
				return true
			} else if len(vr2) == 0 {
				return false
			}

			v1, v2 := vr1[0], vr2[0]
			if v1.Version == v2.Version {
				return byPackage(m1, m2)
			}

			return version.Before(v1.Version, v2.Version)
		}

		// Sort by module base name then major version.
		base1, major1, ok1 := module.SplitPathVersion(m1.Module)
		base2, major2, ok2 := module.SplitPathVersion(m2.Module)
		if !ok1 || !ok2 {
			return m1.Module < m2.Module
		}

		if base1 == base2 {
			i1, ok1 := majorToInt(major1)
			i2, ok2 := majorToInt(major2)
			if ok1 && ok2 {
				return i1 < i2
			}
			return major1 < major2
		}

		return base1 < base2
	})
}

// merge merges all modules with the same module & package info
// (but possibly different versions) into one.
func merge(ms []*Module) ([]*Module, error) {
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

	// only run if m1 and m2 are same except versions
	// deletes vulnerable_at if set
	merge := func(m1, m2 *Module) (*Module, error) {
		merged, err := m1.Versions.mergeStrict(m2.Versions)
		if err != nil {
			return nil, fmt.Errorf("could not merge versions of module %s: %w", m1.Module, err)
		}
		return &Module{
			Module:              m1.Module,
			Versions:            merged,
			UnsupportedVersions: m1.UnsupportedVersions.merge(m2.UnsupportedVersions),
			NonGoVersions:       m1.NonGoVersions.merge(m2.NonGoVersions),
			Packages:            m1.Packages,
		}, nil
	}

	modules := make(map[compMod]*Module)
	for _, m := range ms {
		c := toCompMod(m)
		mod, ok := modules[c]
		if !ok {
			modules[c] = m
		} else {
			merged, err := merge(mod, m)
			if err != nil {
				// For now, bail out if any module can't be merged.
				// This could be improved by continuing to try even if
				// some merges fail.
				return nil, err
			}
			modules[c] = merged
		}
	}

	return maps.Values(modules), nil
}

func (v Versions) merge(v2 Versions) Versions {
	merged := append(slices.Clone(v), v2...)
	merged.fix()
	return merged
}

func (v Versions) mergeStrict(v2 Versions) (merged Versions, _ error) {
	merged = v.merge(v2)
	ranges, err := merged.ToSemverRanges()
	if err != nil {
		return nil, err
	}
	if err := osvutils.ValidateRanges(ranges); err != nil {
		return nil, err
	}
	return merged, nil
}

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
	r.References = slices.DeleteFunc(r.References, func(ref *Reference) bool {
		return ref.Type == osv.ReferenceTypePackage ||
			idstr.IsGoAdvisory(ref.URL)
	})

	re := newRE(r)

	aliases := r.Aliases()
	for _, ref := range r.References {
		switch re.Type(ref.URL, aliases) {
		case urlTypeAdvisory:
			ref.Type = osv.ReferenceTypeAdvisory
		case urlTypeIssue:
			ref.Type = osv.ReferenceTypeReport
		case urlTypeFix:
			ref.Type = osv.ReferenceTypeFix
		case urlTypeWeb:
			ref.Type = osv.ReferenceTypeWeb
		}
	}

	// If this is a reviewed report, attempt to find the "best" advisory and delete others.
	if r.IsReviewed() {
		if bestAdvisory := bestAdvisory(r.References, r.Aliases()); bestAdvisory != "" {
			isNotBest := func(ref *Reference) bool {
				return ref.Type == osv.ReferenceTypeAdvisory && ref.URL != bestAdvisory
			}
			r.References = slices.DeleteFunc(r.References, isNotBest)
		}
	}

	if r.countAdvisories() == 0 && r.needsAdvisory() {
		if r.hasExternalSource() {
			r.addSourceAdvisory()
		} else if as := r.Aliases(); len(as) > 0 {
			r.addAdvisory(as[0])
		}
	}

	slices.SortFunc(r.References, func(a *Reference, b *Reference) int {
		if a.Type == b.Type {
			return strings.Compare(a.URL, b.URL)
		}
		return strings.Compare(string(a.Type), string(b.Type))
	})

	if len(r.References) == 0 {
		r.References = nil
	}
}

func (r *Report) hasExternalSource() bool {
	return r.SourceMeta != nil && idstr.IsIdentifier(r.SourceMeta.ID)
}

func (r *Report) addAdvisory(id string) {
	if link := idstr.AdvisoryLink(id); link != "" {
		r.References = append(r.References, &Reference{
			Type: osv.ReferenceTypeAdvisory,
			URL:  link,
		})
	}
}

func (r *Report) addSourceAdvisory() {
	srcID := r.SourceMeta.ID
	for _, ref := range r.References {
		if idstr.IsAdvisoryFor(ref.URL, srcID) {
			ref.Type = osv.ReferenceTypeAdvisory
			return
		}
	}
	r.addAdvisory(srcID)
}

// bestAdvisory returns the URL of the "best" advisory in the references,
// or ("", false) if none can be found.
// Repository-level GHSAs are considered the best, followed by regular
// GHSAs, followed by CVEs.
// For now, if there are advisories mentioning two or more
// aliases of the same type, we don't try to determine which is best.
// (For example, if there are two advisories, referencing GHSA-1 and GHSA-2, we leave it
// to the triager to pick the best one.)
func bestAdvisory(refs []*Reference, aliases []string) string {
	bestAdvisory := ""
	bestType := advisoryTypeUnknown
	ghsas, cves := make(map[string]bool), make(map[string]bool)
	for _, ref := range refs {
		if ref.Type != osv.ReferenceTypeAdvisory {
			continue
		}
		alias, ok := idstr.IsAdvisoryForOneOf(ref.URL, aliases)
		if !ok {
			continue
		}
		if t := advisoryTypeOf(ref.URL); t > bestType {
			bestAdvisory = ref.URL
			bestType = t
		}

		if idstr.IsGHSA(alias) {
			ghsas[alias] = true
		} else if idstr.IsCVE(alias) {
			cves[alias] = true
		}
	}

	if len(ghsas) > 1 || len(cves) > 1 {
		return ""
	}

	return bestAdvisory
}

type urlType int

const (
	urlTypeUnknown urlType = iota
	urlTypeIssue
	urlTypeFix
	urlTypeAdvisory
	urlTypeWeb
)

func (re *reportRE) Type(url string, aliases []string) urlType {
	if _, ok := idstr.IsAdvisoryForOneOf(url, aliases); ok {
		return urlTypeAdvisory
	} else if idstr.IsAdvisory(url) {
		// URLs that point to other vulns should not be considered
		// advisories for this vuln.
		return urlTypeWeb
	}

	switch {
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

func advisoryTypeOf(url string) advisoryType {
	switch {
	case idstr.IsCVELink(url):
		return advisoryTypeCVE
	case idstr.IsGHSAGlobalLink(url):
		return advisoryTypeGHSA
	case idstr.IsGHSARepoLink(url):
		return advisoryTypeGHSARepo
	}
	return advisoryTypeUnknown
}

type reportRE struct {
	issue, fix *regexp.Regexp
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
		issue: regexp.MustCompile(`^https://` + moduleRE + `/issue(s?)/.*$`),
		fix:   regexp.MustCompile(`^https://` + moduleRE + `/(commit(s?)|pull)/.*$`),
	}
}
