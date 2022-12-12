// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/internal/stdlib"
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

func getCanonicalModVersionFromProxy(path, version string) (_ string, err error) {
	escaped, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	b, err := proxyLookup(fmt.Sprintf("%s/@v/%v.info", escaped, version))
	if err != nil {
		return "", err
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	ver, ok := v["Version"].(string)
	if !ok {
		return "", fmt.Errorf("unable to retrieve canonical version for %s", version)
	}
	return ver, nil
}

func checkModVersions(modPath string, vrs []VersionRange) (err error) {
	checkVersion := func(v Version) error {
		if v == "" {
			return nil
		}
		if err := module.Check(modPath, v.V()); err != nil {
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

func (m *Module) lintStdLib(addPkgIssue func(string)) {
	if len(m.Packages) == 0 {
		addPkgIssue("missing package")
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			addPkgIssue("missing package")
		}
	}
}

func (m *Module) lintThirdParty(addPkgIssue func(string)) {
	if m.Module == "" {
		addPkgIssue("missing module")
		return
	}
	if err := checkModVersions(m.Module, m.Versions); err != nil {
		addPkgIssue(err.Error())
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			addPkgIssue("missing package")
			continue
		}
		if !strings.HasPrefix(p.Package, m.Module) {
			addPkgIssue("module must be a prefix of package")
		}
		if err := module.CheckImportPath(p.Package); err != nil {
			addPkgIssue(err.Error())
		}
	}
}

func (m *Module) lintVersions(addPkgIssue func(string)) {
	if m.VulnerableAt != "" && !m.VulnerableAt.IsValid() {
		addPkgIssue(fmt.Sprintf("invalid vulnerable_at semantic version: %q", m.VulnerableAt))
	}
	for i, vr := range m.Versions {
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
		for _, vrPrev := range m.Versions[:i] {
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
		if r.CVEMetadata.CWE == "" {
			addIssue("cve_metadata.cwe is required")
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

// Regex patterns for standard links.
var (
	prRegex       = regexp.MustCompile(`https://go.dev/cl/\d+`)
	commitRegex   = regexp.MustCompile(`https://go.googlesource.com/[^/]+/\+/([^/]+)`)
	issueRegex    = regexp.MustCompile(`https://go.dev/issue/\d+`)
	announceRegex = regexp.MustCompile(`https://groups.google.com/g/golang-(announce|dev|nuts)/c/([^/]+)`)

	nistRegex  = regexp.MustCompile(`^https://nvd.nist.gov/vuln/detail/(CVE-.*)$`)
	ghsaRegex  = regexp.MustCompile(`^https://github.com/.*/(GHSA-[^/]+)$`)
	mitreRegex = regexp.MustCompile(`^https://cve.mitre.org/.*(CVE-[\d\-]+)$`)
)

// Checks that the "links" section of a Report for a package in the
// standard library contains all necessary links, and no third-party links.
func (r *Report) lintStdLibLinks(addIssue func(string)) {
	var (
		hasFixLink      = false
		hasReportLink   = false
		hasAnnounceLink = false
	)
	for _, ref := range r.References {
		switch ref.Type {
		case ReferenceTypeAdvisory:
			addIssue(fmt.Sprintf("%q: advisory reference should not be set for first-party issues", ref.URL))
		case ReferenceTypeFix:
			hasFixLink = true
			if !prRegex.MatchString(ref.URL) && !commitRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: fix reference should match %q or %q", ref.URL, prRegex, commitRegex))
			}
		case ReferenceTypeReport:
			hasReportLink = true
			if !issueRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: report reference should match %q", ref.URL, issueRegex))
			}
		case ReferenceTypeWeb:
			if !announceRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: web references should only contain announcement links matching %q", ref.URL, announceRegex))
			} else {
				hasAnnounceLink = true
			}
		}
	}
	if !hasFixLink {
		addIssue("references should contain at least one fix")
	}
	if !hasReportLink {
		addIssue("references should contain at least one report")
	}
	if !hasAnnounceLink {
		addIssue(fmt.Sprintf("references should contain an announcement link matching %q", announceRegex))
	}
}

func (r *Report) lintLinks(addIssue func(string)) {
	advisoryCount := 0
	for _, ref := range r.References {
		if !slices.Contains(ReferenceTypes, ref.Type) {
			addIssue(fmt.Sprintf("%q is not a valid reference type", ref.Type))
		}
		l := ref.URL
		if _, err := url.ParseRequestURI(l); err != nil {
			addIssue(fmt.Sprintf("%q is not a valid URL", l))
		}
		if fixed := fixURL(l); fixed != l {
			addIssue(fmt.Sprintf("unfixed url: %q should be %q", l, fixURL(l)))
		}
		if ref.Type == ReferenceTypeAdvisory {
			advisoryCount++
		}
		if ref.Type != ReferenceTypeAdvisory {
			// An ADVISORY reference to a CVE/GHSA indicates that it
			// is the canonical source of information on this vuln.
			//
			// A reference to a CVE/GHSA that is not an alias of this
			// report indicates that it may contain related information.
			//
			// A reference to a CVE/GHSA that appears in the CVEs/GHSAs
			// aliases is redundant.
			for _, re := range []*regexp.Regexp{nistRegex, mitreRegex, ghsaRegex} {
				if m := re.FindStringSubmatch(ref.URL); len(m) > 0 {
					id := m[1]
					if slices.Contains(r.CVEs, id) || slices.Contains(r.GHSAs, id) {
						addIssue(fmt.Sprintf("redundant non-advisory reference to %v", id))
					}
				}
			}
		}
	}
	if advisoryCount > 1 {
		addIssue("references should contain at most one advisory link")
	}
}

// Lint checks the content of a Report and outputs a list of strings
// representing lint errors.
// TODO: It might make sense to include warnings or informational things
// alongside errors, especially during for use during the triage process.
func (r *Report) Lint(filename string) []string {
	var issues []string

	addIssue := func(iss string) {
		issues = append(issues, iss)
	}
	isStdLibReport := false
	isExcluded := false
	switch filepath.Base(filepath.Dir(filename)) {
	case "reports":
		if r.Excluded != "" {
			addIssue("report in reports/ must not have excluded set")
		}
		if len(r.Modules) == 0 {
			addIssue("no modules")
		}
		if r.Description == "" {
			addIssue("missing description")
		}

	case "excluded":
		isExcluded = true
		if r.Excluded == "" {
			addIssue("report in excluded/ must have excluded set")
		} else if !slices.Contains(ExcludedReasons, r.Excluded) {
			addIssue(fmt.Sprintf("excluded (%q) is not in set %v", r.Excluded, ExcludedReasons))
		} else if r.Excluded != "NOT_GO_CODE" && len(r.Modules) == 0 {
			addIssue("no modules")
		}
		if len(r.CVEs) == 0 && len(r.GHSAs) == 0 {
			addIssue("excluded report must have at least one associated CVE or GHSA")
		}
	}

	for i, m := range r.Modules {
		addPkgIssue := func(iss string) {
			addIssue(fmt.Sprintf("modules[%v]: %v", i, iss))
		}
		if m.Module == stdlib.ModulePath || m.Module == stdlib.ToolchainModulePath {
			isStdLibReport = true
			m.lintStdLib(addPkgIssue)
		} else {
			m.lintThirdParty(addPkgIssue)
		}
		for _, p := range m.Packages {
			if strings.HasPrefix(p.Package, fmt.Sprintf("%s/", stdlib.ToolchainModulePath)) && m.Module != stdlib.ToolchainModulePath {
				addPkgIssue(fmt.Sprintf(`%q should be in module "%s", not %q`, p.Package, stdlib.ToolchainModulePath, m.Module))
			}
		}

		m.lintVersions(addPkgIssue)
	}

	r.lintLineLength("description", r.Description, addIssue)
	if r.CVEMetadata != nil {
		r.lintLineLength("cve_metadata.description", r.CVEMetadata.Description, addIssue)
	}
	r.lintCVEs(addIssue)

	if isStdLibReport && !isExcluded {
		r.lintStdLibLinks(addIssue)
	}

	r.lintLinks(addIssue)

	return issues
}

var commitHashRegex = regexp.MustCompile(`^[a-f0-9]+$`)

func (r *Report) Fix() {
	for _, ref := range r.References {
		ref.URL = fixURL(ref.URL)
	}
	fixVersion := func(mod string, vp *Version) {
		v := *vp
		if v == "" {
			return
		}
		if commitHashRegex.MatchString(string(v)) {
			if c, err := getCanonicalModVersionFromProxy(mod, string(v)); err == nil {
				v = Version(c)
			}
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
	for _, m := range r.Modules {
		for i := range m.Versions {
			fixVersion(m.Module, &m.Versions[i].Introduced)
			fixVersion(m.Module, &m.Versions[i].Fixed)
		}
		fixVersion(m.Module, &m.VulnerableAt)
	}
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

// FindModuleFromPackage checks that module path leads to a module in the proxy
// server, then trims the path until it does or uses the full path from the issue
// title if a working module path cannot be found.
func FindModuleFromPackage(path string) string {
	for temp := path; temp != "."; temp = filepath.Dir(temp) {
		escaped, err := module.EscapePath(temp)
		if err != nil {
			return path
		}
		url := fmt.Sprintf("https://proxy.golang.org/%s/@v/list", escaped)
		resp, err := http.Get(url)
		if err != nil {
			return path
		} else if resp.StatusCode == 200 {
			return temp
		}
	}
	return path
}
