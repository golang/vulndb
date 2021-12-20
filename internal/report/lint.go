// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/internal/derrors"
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
	b, err := ioutil.ReadAll(resp.Body)
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
	b, err := ioutil.ReadAll(resp.Body)
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
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadDir(%q): %v", filename, err)
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
func (vuln *Report) Lint() []string {
	var issues []string

	addIssue := func(iss string) {
		issues = append(issues, iss)
	}

	var importPath string
	if !vuln.Stdlib {
		if vuln.Module == "" {
			addIssue("missing module")
		}
		if vuln.Module != "" && vuln.Package == vuln.Module {
			addIssue("package is redundant and can be removed")
		}
		if vuln.Package != "" && !strings.HasPrefix(vuln.Package, vuln.Module) {
			addIssue("module must be a prefix of package")
		}
		if vuln.Package == "" {
			importPath = vuln.Module
		} else {
			importPath = vuln.Package
		}
		if vuln.Module != "" && importPath != "" {
			if err := checkModVersions(vuln.Module, vuln.Versions); err != nil {
				addIssue(err.Error())
			}

			if err := module.CheckImportPath(importPath); err != nil {
				addIssue(err.Error())
			}
		}
	} else if vuln.Package == "" {
		addIssue("missing package")
	}

	for _, additionalPackage := range vuln.AdditionalPackages {
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
		if !vuln.Stdlib {
			if err := checkModVersions(additionalPackage.Module, additionalPackage.Versions); err != nil {
				addIssue(err.Error())
			}
		}
	}

	if vuln.Description == "" {
		addIssue("missing description")
	}

	if vuln.Published.IsZero() {
		addIssue("missing published")
	}

	if vuln.LastModified != nil && vuln.LastModified.Before(vuln.Published) {
		addIssue("last_modified is before published")
	}

	if vuln.CVE != "" && len(vuln.CVEs) > 0 {
		addIssue("use only one of CVE and CVEs")
	}

	if vuln.CVE != "" && vuln.CVEMetadata != nil && vuln.CVEMetadata.ID != "" {
		// TODO: may just want to use one of these? :shrug:
		addIssue("only one of cve and cve_metadata.id should be present")
	}

	if vuln.CVE != "" && !cveRegex.MatchString(vuln.CVE) {
		issues = append(issues, "malformed cve identifier")
	}
	for _, cve := range vuln.CVEs {
		if !cveRegex.MatchString(cve) {
			addIssue("malformed cve identifier")
		}
	}

	if vuln.CVEMetadata != nil {
		if vuln.CVEMetadata.ID == "" {
			addIssue("cve_metadata.id is required")
		}
		if !cveRegex.MatchString(vuln.CVEMetadata.ID) {
			addIssue("malformed cve_metadata.id identifier")
		}
	}

	return issues
}
