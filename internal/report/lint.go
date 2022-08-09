// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/internal/derrors"
)

// TODO: getting things from the proxy should all be cached so we
// aren't re-requesting the same stuff over and over.

var proxyURL = "https://proxy.golang.org"

func init() {
	if proxy, ok := os.LookupEnv("GOPROXY"); ok {
		proxyURL = proxy
	}
}

func proxyLookup(urlSuffix string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", proxyURL, urlSuffix)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http.Get(%q) returned status %v", url, resp.Status)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func getModVersionsFromProxy(path string) (_ map[string]bool, err error) {
	escaped, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	b, err := proxyLookup(fmt.Sprintf("%s/@v/list", escaped))
	if err != nil {
		return nil, err
	}
	versions := map[string]bool{}
	for _, v := range strings.Split(string(b), "\n") {
		versions[v] = true
	}
	return versions, nil
}

func getCanonicalModNameFromProxy(path, version string) (_ string, err error) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	b, err := proxyLookup(fmt.Sprintf("%s/@v/%s.mod", escapedPath, escapedVersion))
	if err != nil {
		return "", err
	}
	m, err := modfile.ParseLax("go.mod", b, nil)
	if err != nil {
		return "", err
	}
	if m.Module == nil {
		return "", fmt.Errorf("unable to retrieve module information for %s", path)
	}
	return m.Module.Mod.Path, nil
}

var pseudoVersionRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// isPseudoVersion reports whether v is a pseudo-version.
// NOTE: this is taken from cmd/go/internal/modfetch/pseudo.go but
// uses regexp instead of the internal lazyregex package.
func isPseudoVersion(v string) bool {
	return strings.Count(v, "-") >= 2 && semver.IsValid(v) && pseudoVersionRE.MatchString(v)
}

func versionExists(version string, versions map[string]bool) (err error) {
	// TODO: for now, don't check validity of pseudo-versions.
	// We should add a check that the pseudo-version could feasibly exist given
	// the actual versions that we know about.
	//
	// The pseudo-version check should probably take into account the canonical
	// import path (investigate cmd/go/internal/modfetch/coderepo.go has, which
	// has something like this, check the error containing "has post-%v module
	// path").
	if isPseudoVersion(version) {
		return nil
	}
	if !versions[version] {
		return fmt.Errorf("proxy unaware of version")
	}
	return nil
}

func checkModVersions(modPath string, vrs []VersionRange) (err error) {
	foundVersions, err := getModVersionsFromProxy(modPath)
	if err != nil {
		return fmt.Errorf("unable to retrieve module versions from proxy: %s", err)
	}
	checkVersion := func(v Version) error {
		if v == "" {
			return nil
		}
		if err := module.Check(modPath, v.V()); err != nil {
			return err
		}
		if err := versionExists(v.V(), foundVersions); err != nil {
			return err
		}
		canonicalPath, err := getCanonicalModNameFromProxy(modPath, v.V())
		if err != nil {
			return fmt.Errorf("unable to retrieve canonical module path from proxy: %s", err)
		}
		if canonicalPath != modPath {
			return fmt.Errorf("invalid module path %q at version %q (canonical path is %q)", modPath, v, canonicalPath)
		}
		return nil
	}
	for _, vr := range vrs {
		for _, v := range []Version{vr.Introduced, vr.Fixed} {
			if err := checkVersion(v); err != nil {
				return fmt.Errorf("bad version %q: %s", v, err)
			}
		}
	}
	return nil
}

// LintFile is used to lint the reports/ directory. It is run by
// TestLintReports (in the vulndb repo) to ensure that there are no errors in
// the YAML reports.
func LintFile(filename string) (_ []string, err error) {
	defer derrors.Wrap(&err, "LintFile(%q)", filename)
	r, err := Read(filename)
	if err != nil {
		return nil, err
	}
	return r.Lint(), nil
}

func (p *Package) lintStdLibPkg(addPkgIssue func(string)) {
	if p.Package == "" {
		addPkgIssue("missing package")
	}
}

func (p *Package) lintThirdPartyPkg(addPkgIssue func(string)) {
	if p.Module == "" {
		addPkgIssue("missing module")
		return
	}
	if p.Package == p.Module {
		addPkgIssue("package is redundant and can be removed")
	}
	if p.Package != "" && !strings.HasPrefix(p.Package, p.Module) {
		addPkgIssue("module must be a prefix of package")
	}
	if err := checkModVersions(p.Module, p.Versions); err != nil {
		addPkgIssue(err.Error())
	}

	importPath := p.Package
	if p.Package == "" {
		importPath = p.Module
	}
	if err := module.CheckImportPath(importPath); err != nil {
		addPkgIssue(err.Error())
	}
}

func (p *Package) lintVersions(addPkgIssue func(string)) {
	if p.VulnerableAt != "" && !p.VulnerableAt.IsValid() {
		addPkgIssue(fmt.Sprintf("invalid vulnerable_at semantic version: %q", p.VulnerableAt))
	}
	for i, vr := range p.Versions {
		for _, v := range []Version{vr.Introduced, vr.Fixed} {
			if v != "" && !v.IsValid() {
				addPkgIssue(fmt.Sprintf("invalid semantic version: %q", v))
			}
		}
		if vr.Fixed != "" && !vr.Introduced.Before(vr.Fixed) {
			addPkgIssue(
				fmt.Sprintf("version %q >= %q", vr.Introduced, vr.Fixed))
			continue
		}
		// Check all previous version ranges to ensure none overlap with
		// this one.
		for _, vrPrev := range p.Versions[:i] {
			if vrPrev.Introduced.Before(vr.Fixed) && vr.Introduced.Before(vrPrev.Fixed) {
				addPkgIssue(fmt.Sprintf("version ranges overlap: [%v,%v), [%v,%v)", vr.Introduced, vr.Fixed, vr.Introduced, vrPrev.Fixed))
			}
		}
	}
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (r *Report) lintCVEs(addIssue func(string)) {
	if len(r.CVEs) > 0 && r.CVEMetadata != nil && r.CVEMetadata.ID != "" {
		// TODO: consider removing one of these fields from the Report struct.
		addIssue("only one of cve and cve_metadata.id should be present")
	}

	for _, cve := range r.CVEs {
		if !cveRegex.MatchString(cve) {
			addIssue("malformed cve identifier")
		}
	}

	if r.CVEMetadata != nil {
		if r.CVEMetadata.ID == "" {
			addIssue("cve_metadata.id is required")
		} else if !cveRegex.MatchString(r.CVEMetadata.ID) {
			addIssue("malformed cve_metadata.id identifier")
		}
	}
}

func (r *Report) lintLineLength(field, content string, addIssue func(string)) {
	const maxLineLength = 100
	for _, line := range strings.Split(content, "\n") {
		if len(line) <= maxLineLength {
			continue
		}
		if !strings.Contains(content, " ") {
			continue // A single long word is OK.
		}
		addIssue(fmt.Sprintf("%v contains line > %v characters long", field, maxLineLength))
		return
	}
}

// Regex patterns for standard library links.
var (
	prRegex       = regexp.MustCompile(`https://go.dev/cl/\d+`)
	commitRegex   = regexp.MustCompile(`https://go.googlesource.com/[^/]+/\+/([^/]+)`)
	issueRegex    = regexp.MustCompile(`https://go.dev/issue/\d+`)
	announceRegex = regexp.MustCompile(`https://groups.google.com/g/golang-(announce|dev|nuts)/c/([^/]+)`)
)

func isFirstPartyGoLink(l string) bool {
	return prRegex.MatchString(l) || commitRegex.MatchString(l) || issueRegex.MatchString(l) || announceRegex.MatchString(l)
}

// Checks that the "links" section of a Report for a package in the
// standard library contains all necessary links, and no third-party links.
func (r *Report) lintStdLibLinks(addIssue func(string)) {
	if r.Links.PR == "" && r.Links.Commit == "" {
		addIssue("at least one of links.pr and links.commit must be set")
	}
	if r.Links.PR != "" && !prRegex.MatchString(r.Links.PR) {
		addIssue(fmt.Sprintf("links.pr should contain a PR link matching %q", prRegex))
	}
	if r.Links.Commit != "" && !commitRegex.MatchString(r.Links.Commit) {
		addIssue(fmt.Sprintf("links.commit commit link should match %q", commitRegex))
	}
	if r.Links.Advisory != "" {
		addIssue("links.advisory should not be set for first-party issues")
	}
	hasIssueLink := false
	hasAnnounceLink := false
	for _, c := range r.Links.Context {
		if issueRegex.MatchString(c) {
			hasIssueLink = true
		} else if announceRegex.MatchString(c) {
			hasAnnounceLink = true
		}

		if !isFirstPartyGoLink(c) {
			addIssue(fmt.Sprintf("links.context should contain only PR, commit, issue and announcement links, remove or fix %q", c))
		}
	}
	if !hasIssueLink {
		addIssue(fmt.Sprintf("links.context should contain an issue link matching %q", issueRegex))
	}
	if !hasAnnounceLink {
		addIssue(fmt.Sprintf("links.context should contain an announcement link matching %q", announceRegex))
	}
}

func (r *Report) lintLinks(addIssue func(string)) {
	links := append(r.Links.Context, r.Links.Advisory, r.Links.Commit, r.Links.PR)
	for _, l := range links {
		if l == "" {
			continue
		}
		if _, err := url.ParseRequestURI(l); err != nil {
			addIssue(fmt.Sprintf("%q is not a valid URL", l))
		}
		if fixed := fixURL(l); fixed != l {
			addIssue(fmt.Sprintf("unfixed url: %q should be %q", l, fixURL(l)))
		}
	}
}

// Lint checks the content of a Report and outputs a list of strings
// representing lint errors.
// TODO: It might make sense to include warnings or informational things
// alongside errors, especially during for use during the triage process.
func (r *Report) Lint() []string {
	var issues []string

	addIssue := func(iss string) {
		issues = append(issues, iss)
	}

	if len(r.Packages) == 0 {
		addIssue("no packages")
	}

	isStdLibReport := false
	for i, p := range r.Packages {
		addPkgIssue := func(iss string) {
			addIssue(fmt.Sprintf("packages[%v]: %v", i, iss))
		}

		if p.Module == "std" {
			isStdLibReport = true
			p.lintStdLibPkg(addPkgIssue)
		} else {
			p.lintThirdPartyPkg(addPkgIssue)
		}

		p.lintVersions(addPkgIssue)
	}

	if r.Description == "" {
		addIssue("missing description")
	}
	if r.LastModified != nil && r.LastModified.Before(r.Published) {
		addIssue("last_modified is before published")
	}

	r.lintLineLength("description", r.Description, addIssue)
	if r.CVEMetadata != nil {
		r.lintLineLength("cve_metadata.description", r.CVEMetadata.Description, addIssue)
	}
	r.lintCVEs(addIssue)

	r.lintLinks(addIssue)
	if isStdLibReport {
		r.lintStdLibLinks(addIssue)
	}

	return issues
}

func (r *Report) Fix() {
	r.Links.Commit = fixURL(r.Links.Commit)
	r.Links.PR = fixURL(r.Links.PR)
	r.Links.Advisory = fixURL(r.Links.Advisory)
	var fixed []string
	for _, l := range r.Links.Context {
		fixed = append(fixed, fixURL(l))
	}
	fixVersion := func(vp *Version) {
		v := *vp
		if v == "" {
			return
		}
		v = Version(strings.TrimPrefix(string(v), "v"))
		v = Version(strings.TrimPrefix(string(v), "go"))
		if v.IsValid() {
			build := semver.Build(v.V())
			v = Version(v.Canonical())
			if build != "" {
				v += Version(build)
			}
		}
		*vp = v
	}
	for i, p := range r.Packages {
		if p.Package == p.Module {
			p.Package = ""
		}
		for j := range p.Versions {
			fixVersion(&r.Packages[i].Versions[j].Introduced)
			fixVersion(&r.Packages[i].Versions[j].Fixed)
		}
		fixVersion(&r.Packages[i].VulnerableAt)
	}
	r.Links.Context = fixed
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
