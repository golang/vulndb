// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/internal/derrors"
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

func getModVersions(path string) (_ map[string]bool, err error) {
	defer derrors.Wrap(&err, "getModVersions(%q)", path)
	escaped, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(fmt.Sprintf("%s/%s/@v/list", proxyURL, escaped))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	versions := map[string]bool{}
	for _, v := range strings.Split(string(b), "\n") {
		versions[v] = true
	}
	return versions, nil
}

func getCanonicalModName(path, version string) (_ string, err error) {
	defer derrors.Wrap(&err, "getCanonicalModName(%q, %q)", path, version)
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	resp, err := http.Get(fmt.Sprintf("%s/%s/@v/%s.mod", proxyURL, escapedPath, escapedVersion))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
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
	defer derrors.Wrap(&err, "versionExists(%q, %v)", version, versions)
	// TODO: for now, just skip pseudo-versions. at some point we should verify that
	// it is a likely pseudo-version, i.e. one that could feasibly exist given the
	// actual versions that we know about.
	//
	// pseudo-version check should take into account the canonical import path
	// probably? (I think cmd/go/internal/modfetch/coderepo.go has something like
	// this, check the error containing "has post-%v module path")
	if isPseudoVersion(version) {
		return nil
	}
	if !versions[version] {
		return fmt.Errorf("proxy unaware of version")
	}
	return nil
}

func checkModVersions(path string, vr []VersionRange) (err error) {
	defer derrors.Wrap(&err, "checkModVersions(%q, vr)", path)
	realVersions, err := getModVersions(path)
	if err != nil {
		return fmt.Errorf("unable to retrieve module versions from proxy: %s", err)
	}
	checkVersion := func(version Version) error {
		if !version.IsValid() {
			return errors.New("invalid module semver")
		}
		if err := module.Check(path, version.V()); err != nil {
			return err
		}
		if err := versionExists(version.V(), realVersions); err != nil {
			return err
		}
		canonicalPath, err := getCanonicalModName(path, version.V())
		if err != nil {
			return err
		}
		if canonicalPath != path {
			return fmt.Errorf("invalid module path at version (canonical path is %s)", canonicalPath)
		}
		return nil
	}
	for _, version := range vr {
		if version.Introduced != "" {
			if err := checkVersion(version.Introduced); err != nil {
				return fmt.Errorf("bad version.introduced %q: %s", version.Introduced, err)
			}
		}
		if version.Fixed != "" {
			if err := checkVersion(version.Fixed); err != nil {
				return fmt.Errorf("bad version.fixed %q: %s", version.Fixed, err)
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

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Lint checks the content of a Report.
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

	for i, p := range r.Packages {
		addPkgIssue := func(iss string) {
			issues = append(issues, fmt.Sprintf("packages[%v]: %v", i, iss))
		}
		if !stdlib.Contains(p.Module) {
			if p.Module == "" {
				addPkgIssue("missing module")
			}
			if p.Module != "" && p.Package == p.Module {
				addPkgIssue("package is redundant and can be removed")
			}
			if p.Package != "" && !strings.HasPrefix(p.Package, p.Module) {
				addPkgIssue("module must be a prefix of package")
			}
			var importPath string
			if p.Package == "" {
				importPath = p.Module
			} else {
				importPath = p.Package
			}
			if p.Module != "" && importPath != "" {
				if err := checkModVersions(p.Module, p.Versions); err != nil {
					addPkgIssue(err.Error())
				}

				if err := module.CheckImportPath(importPath); err != nil {
					addPkgIssue(err.Error())
				}
			}
		} else {
			if p.Package == "" {
				addPkgIssue("missing package")
			}
		}
		for i, v1 := range p.Versions {
			for _, v := range []Version{v1.Introduced, v1.Fixed} {
				if v == "" {
					continue
				}
				if !v.IsValid() {
					addPkgIssue(fmt.Sprintf("invalid semantic version: %q", v))
				}
			}
			if v1.Introduced != "" && v1.Fixed != "" && !v1.Introduced.Before(v1.Fixed) {
				addPkgIssue(fmt.Sprintf("version %q >= %q", p.Versions[i].Introduced, p.Versions[i].Fixed))
				continue
			}
			for j, v2 := range p.Versions[:i] {
				if v2.Introduced.Before(v1.Fixed) && v1.Introduced.Before(v2.Fixed) {
					addPkgIssue(fmt.Sprintf("version ranges overlap: [%v,%v), [%v,%v)", p.Versions[i].Introduced, p.Versions[i].Fixed, p.Versions[j].Introduced, p.Versions[j].Fixed))
				}
			}
		}
	}

	if r.Description == "" {
		addIssue("missing description")
	}

	if r.LastModified != nil && r.LastModified.Before(r.Published) {
		addIssue("last_modified is before published")
	}

	if len(r.CVEs) > 0 && r.CVEMetadata != nil && r.CVEMetadata.ID != "" {
		// TODO: may just want to use one of these? :shrug:
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
		}
		if !cveRegex.MatchString(r.CVEMetadata.ID) {
			addIssue("malformed cve_metadata.id identifier")
		}
	}
	links := append(r.Links.Context, r.Links.Commit, r.Links.PR)
	for _, l := range links {
		if !isValidURL(l) {
			addIssue(fmt.Sprintf("%q should be %q", l, fixURL(l)))
		}
	}
	return issues
}

func (r *Report) Fix() {
	r.Links.Commit = fixURL(r.Links.Commit)
	r.Links.PR = fixURL(r.Links.PR)
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
				v += Version("+" + build)
			}
		}
		*vp = v
	}
	for i, p := range r.Packages {
		for j, _ := range p.Versions {
			fixVersion(&r.Packages[i].Versions[j].Introduced)
			fixVersion(&r.Packages[i].Versions[j].Fixed)
		}
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
}}

func isValidURL(u string) bool {
	return fixURL(u) == u
}

func fixURL(u string) string {
	for _, repl := range urlReplacements {
		u = repl.re.ReplaceAllString(u, repl.repl)
	}
	return u
}
