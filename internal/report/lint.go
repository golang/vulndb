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
	"gopkg.in/yaml.v2"
)

// TODO: getting things from the proxy should all be cached so we
// aren't re-requesting the same stuff over and over.

var proxyURL = "https://proxy.golang.org"

func init() {
	if proxy, ok := os.LookupEnv("GOPROXY"); ok {
		proxyURL = proxy
	}
}

func getModVersions(module string) (_ map[string]bool, err error) {
	defer derrors.Wrap(&err, "getModVersions(%q)", module)
	resp, err := http.Get(fmt.Sprintf("%s/%s/@v/list", proxyURL, module))
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

func getCanonicalModName(module, version string) (_ string, err error) {
	defer derrors.Wrap(&err, "getCanonicalModName(%q, %q)", module, version)
	resp, err := http.Get(fmt.Sprintf("%s/%s/@v/%s.mod", proxyURL, module, version))
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
		return "", fmt.Errorf("unable to retrieve module information for %s", module)
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
	checkVersion := func(version string) error {
		if !semver.IsValid(version) {
			return errors.New("invalid module semver")
		}
		if err := module.Check(path, version); err != nil {
			return err
		}
		if err := versionExists(version, realVersions); err != nil {
			return err
		}
		canonicalPath, err := getCanonicalModName(path, version)
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
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := yaml.UnmarshalStrict(b, &r); err != nil {
		return nil, fmt.Errorf("yaml.UnmarshalStrict(b, &r): %v (%q)", err, filename)
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

	var importPath string
	if !stdlib.Contains(r.Module) {
		if r.Module == "" {
			addIssue("missing module")
		}
		if r.Module != "" && r.Package == r.Module {
			addIssue("package is redundant and can be removed")
		}
		if r.Package != "" && !strings.HasPrefix(r.Package, r.Module) {
			addIssue("module must be a prefix of package")
		}
		if r.Package == "" {
			importPath = r.Module
		} else {
			importPath = r.Package
		}
		if r.Module != "" && importPath != "" {
			if err := checkModVersions(r.Module, r.Versions); err != nil {
				addIssue(err.Error())
			}

			if err := module.CheckImportPath(importPath); err != nil {
				addIssue(err.Error())
			}
		}
	} else if r.Package == "" {
		addIssue("missing package")
	}

	for _, additionalPackage := range r.AdditionalPackages {
		var additionalImportPath string
		if additionalPackage.Module == "" {
			addIssue("missing additional_package.module")
		}
		if additionalPackage.Package == additionalPackage.Module {
			addIssue("package is redundant and can be removed")
		}
		if additionalPackage.Package != "" && !strings.HasPrefix(additionalPackage.Package, additionalPackage.Module) {
			addIssue("additional_package.module must be a prefix of additional_package.package")
		}
		if additionalPackage.Package == "" {
			additionalImportPath = additionalPackage.Module
		} else {
			additionalImportPath = additionalPackage.Package
		}
		if err := module.CheckImportPath(additionalImportPath); err != nil {
			addIssue(err.Error())
		}
		if !stdlib.Contains(r.Module) {
			if err := checkModVersions(additionalPackage.Module, additionalPackage.Versions); err != nil {
				addIssue(err.Error())
			}
		}
	}

	if r.Description == "" {
		addIssue("missing description")
	}

	if r.Published.IsZero() {
		addIssue("missing published")
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
	r.Links.Context = fixed
}

var urlTermToReplacement = map[string]string{
	"golang.org": "go.dev",
	"groups.google.com/forum/#!topic/golang-announce": "groups.google.com/g/golang-announce/c",
}

func isValidURL(u string) bool {
	return fixURL(u) == u
}

func fixURL(u string) string {
	for term, repl := range urlTermToReplacement {
		if strings.Contains(u, term) {
			return strings.Replace(u, term, repl, 1)
		}
	}
	if strings.Contains(u, "github.com/golang") {
		if strings.Contains(u, "commit") {
			u = strings.Replace(u, "github.com/golang", "go.googlesource.com", 1)
			u = strings.Replace(u, "commit", "+", 1)
			return u
		}
		if strings.Contains(u, "issues") {
			return strings.Replace(u, "github.com/golang/go/issues", "go.dev/issue", 1)
		}
	}
	return u
}
