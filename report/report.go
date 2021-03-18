package report

import (
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

type VersionRange struct {
	Introduced string
	Fixed      string
}

type Report struct {
	Package string
	// TODO: could also be GoToolchain, but we might want
	// this for other things?
	//
	// could we also automate this by just looking for
	// things prefixed with cmd/go?
	DoNotExport bool `json:"do_not_export"`
	// TODO: how does this interact with Versions etc?
	Stdlib bool `json:"stdlib"`
	// TODO: the most common usage of additional package should
	// really be replaced with 'aliases', we'll still need
	// additional packages for some cases, but it's too heavy
	// for most
	AdditionalPackages []struct {
		Package  string
		Symbols  []string
		Versions []VersionRange
	} `toml:"additional_packages"`
	Versions    []VersionRange
	Description string
	Severity    string
	CVE         string
	Credit      string
	Symbols     []string
	OS          []string
	Arch        []string
	Links       struct {
		PR      string
		Commit  string
		Context []string
	}
	CVEMetadata *struct {
		ID          string
		CWE         string
		Description string
	} `toml:"cve_metadata"`
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (vuln *Report) Lint() error {
	if vuln.Package == "" {
		return errors.New("missing package")
	}
	if err := module.CheckImportPath(vuln.Package); err != nil {
		return err
	}

	for _, additionalPackage := range vuln.AdditionalPackages {
		if err := module.CheckImportPath(additionalPackage.Package); err != nil {
			return err
		}
	}

	for _, version := range vuln.Versions {
		if version.Introduced != "" {
			if !semver.IsValid(version.Introduced) {
				return fmt.Errorf("bad version.introduced")
			}
			if err := module.Check(vuln.Package, version.Introduced); err != nil {
				return err
			}
		}
		if version.Fixed != "" {
			if !semver.IsValid(version.Fixed) {
				return fmt.Errorf("bad version.fixed")
			}
			if err := module.Check(vuln.Package, version.Fixed); err != nil {
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
