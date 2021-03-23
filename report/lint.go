package report

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// TODO: getting things from the proxy should all be cached so we
// aren't re-requesting the same stuff over and over.

const proxyURL = "https://proxy.golang.org"

func getModVersions(module string) (map[string]bool, error) {
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

func getCanonicalModName(module string, version string) (string, error) {
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

func versionExists(version string, versions map[string]bool) error {
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

func checkModVersions(path string, vr []VersionRange) error {
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

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (vuln *Report) Lint() error {
	var importPath string
	if !vuln.Stdlib {
		if vuln.Module == "" {
			return errors.New("missing module")
		}
		if vuln.Package == vuln.Module {
			return errors.New("package is redundant and can be removed")
		}
		if vuln.Package != "" && !strings.HasPrefix(vuln.Package, vuln.Module) {
			return errors.New("module must be a prefix of package")
		}
		if vuln.Package == "" {
			importPath = vuln.Module
		} else {
			importPath = vuln.Package
		}
		if err := checkModVersions(vuln.Module, vuln.Versions); err != nil {
			return err
		}

		if err := module.CheckImportPath(importPath); err != nil {
			return err
		}
	} else if vuln.Package == "" {
		return errors.New("missing package")
	}

	for _, additionalPackage := range vuln.AdditionalPackages {
		var additionalImportPath string
		if additionalPackage.Module == "" {
			return errors.New("missing additional_package.module")
		}
		if additionalPackage.Package == additionalPackage.Module {
			return errors.New("package is redundant and can be removed")
		}
		if additionalPackage.Package != "" && !strings.HasPrefix(additionalPackage.Package, additionalPackage.Module) {
			return errors.New("additional_package.module must be a prefix of additional_package.package")
		}
		if additionalPackage.Package == "" {
			additionalImportPath = additionalPackage.Module
		} else {
			additionalImportPath = additionalPackage.Package
		}
		if err := module.CheckImportPath(additionalImportPath); err != nil {
			return err
		}
		if !vuln.Stdlib {
			if err := checkModVersions(additionalPackage.Module, additionalPackage.Versions); err != nil {
				return err
			}
		}
	}

	if vuln.Description == "" {
		return errors.New("missing description")
	}

	sevs := map[string]bool{
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}
	// Could also just default to medium if not provided?
	// Need to document what the default case is and what factors lower
	// or raise the sev
	if vuln.Severity != "" && !sevs[vuln.Severity] {
		return fmt.Errorf("unknown severity %q", vuln.Severity)
	}

	if vuln.CVE != "" && vuln.CVEMetadata != nil && vuln.CVEMetadata.ID != "" {
		// TODO: may just want to use one of these? :shrug:
		return errors.New("only one of cve and cve_metadata.id should be present")
	}

	if vuln.CVE != "" && !cveRegex.MatchString(vuln.CVE) {
		return fmt.Errorf("malformed CVE number: %s", vuln.CVE)
	}

	return nil
}
