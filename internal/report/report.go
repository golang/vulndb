// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package report contains functionality for parsing and linting YAML reports
// in reports/.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/internal/derrors"
	"gopkg.in/yaml.v3"
)

// Version is an SemVer 2.0.0 semantic version with no leading "v" prefix,
// as used by OSV.
type Version string

// V returns the version with a "v" prefix.
func (v Version) V() string {
	return "v" + string(v)
}

// IsValid reports whether v is a valid semantic version string.
func (v Version) IsValid() bool {
	return semver.IsValid(v.V())
}

// Before reports whether v < v2.
func (v Version) Before(v2 Version) bool {
	return semver.Compare(v.V(), v2.V()) < 0
}

// Canonical returns the canonical formatting of the version.
func (v Version) Canonical() string {
	return strings.TrimPrefix(semver.Canonical(v.V()), "v")
}

type VersionRange struct {
	Introduced Version `yaml:"introduced,omitempty"`
	Fixed      Version `yaml:"fixed,omitempty"`
}

type Module struct {
	Module   string         `yaml:",omitempty"`
	Versions []VersionRange `yaml:",omitempty"`
	// Known-vulnerable version, to use when performing static analysis or
	// other techniques on a vulnerable version of the package.
	//
	// In general, we want to use the most recent vulnerable version of
	// the package. Determining this programmatically is difficult, especially
	// for packages without tagged versions, so we specify it manually here.
	VulnerableAt Version    `yaml:"vulnerable_at,omitempty"`
	Packages     []*Package `yaml:",omitempty"`
}

type Package struct {
	Package string   `yaml:",omitempty"`
	GOOS    []string `yaml:"goos,omitempty"`
	GOARCH  []string `yaml:"goarch,omitempty"`
	// Symbols originally identified as vulnerable.
	Symbols []string `yaml:",omitempty"`
	// Additional vulnerable symbols, computed from Symbols via static analysis
	// or other technique.
	DerivedSymbols []string `yaml:"derived_symbols,omitempty"`
}

type LegacyPackage struct {
	Module  string `yaml:",omitempty"`
	Package string `yaml:",omitempty"`
	// Symbols originally identified as vulnerable.
	Symbols []string `yaml:",omitempty"`
	// Additional vulnerable symbols, computed from Symbols via static analysis
	// or other technique.
	DerivedSymbols []string       `yaml:"derived_symbols,omitempty"`
	Versions       []VersionRange `yaml:",omitempty"`
	// Known-vulnerable version, to use when performing static analysis or
	// other techniques on a vulnerable version of the package.
	//
	// In general, we want to use the most recent vulnerable version of
	// the package. Determining this programmatically is difficult, especially
	// for packages without tagged versions, so we specify it manually here.
	VulnerableAt Version `yaml:"vulnerable_at,omitempty"`
}

type Links struct {
	PR       string   `yaml:",omitempty"`
	Commit   string   `yaml:",omitempty"`
	Advisory string   `yaml:",omitempty"`
	Context  []string `yaml:",omitempty"`
}

type CVEMeta struct {
	ID          string `yaml:",omitempty"`
	CWE         string `yaml:",omitempty"`
	Description string `yaml:",omitempty"`
}

// ExcludedReason is the reason a report is excluded from the database.
//
// It must be one of the values in ExcludedReasons.
type ExcludedReason string

// ExcludedReasons are the set of reasons a report may be excluded from the database.
// These are described in detail at
// https://go.googlesource.com/vulndb/+/refs/heads/master/doc/format.md.
var ExcludedReasons = []ExcludedReason{
	"NOT_IMPORTABLE",
	"NOT_GO_CODE",
	"NOT_A_VULNERABILITY",
	"EFFECTIVELY_PRIVATE",
	"DEPENDENT_VULNERABILITY",
}

// Report represents a vulnerability report in the vulndb.
// Remember to update doc/format.md when this structure changes.
type Report struct {
	// TODO: could also be GoToolchain, but we might want
	// this for other things?
	//
	// could we also automate this by just looking for
	// things prefixed with cmd/go?
	DoNotExport bool `yaml:"do_not_export,omitempty"`

	// Excluded indicates an excluded report.
	Excluded ExcludedReason `yaml:",omitempty"`

	Modules []*Module `yaml:",omitempty"`

	// Description is the CVE description from an existing CVE. If we are
	// assigning a CVE ID ourselves, use CVEMetadata.Description instead.
	Description  string     `yaml:",omitempty"`
	Published    time.Time  `yaml:",omitempty"`
	LastModified *time.Time `yaml:"last_modified,omitempty"`
	Withdrawn    *time.Time `yaml:",omitempty"`

	// CVE are CVE IDs for existing CVEs.
	// If we are assigning a CVE ID ourselves, use CVEMetdata.ID instead.
	CVEs []string `yaml:",omitempty"`
	// GHSAs are the IDs of GitHub Security Advisories that match
	// the above CVEs.
	GHSAs []string `yaml:",omitempty"`

	Credit string `yaml:",omitempty"`
	Links  Links  `yaml:",omitempty"`

	// CVEMetdata is used to capture CVE information when we want to assign a
	// CVE ourselves. If a CVE already exists for an issue, use the CVE field
	// to fill in the ID string.
	CVEMetadata *CVEMeta `yaml:"cve_metadata,omitempty"`
}

// GetCVEs returns all CVE IDs for a report.
func (r *Report) GetCVEs() []string {
	if r.CVEMetadata != nil {
		return []string{r.CVEMetadata.ID}
	}
	return r.CVEs
}

// GetAliases returns all aliases (e.g., CVEs, GHSAs) for a report.
func (r *Report) GetAliases() []string {
	return append(r.GetCVEs(), r.GHSAs...)
}

const (
	NISTPrefix    = "https://nvd.nist.gov/vuln/detail/"
	mitrePrefix   = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
	ghsaURLPrefix = "https://github.com/advisories/"
)

// GetAliasLinks returns links to all aliases (e.g., CVEs, GHSAs) for a report,
// unless the link is already the canonical advisory.
func (r *Report) GetAliasLinks() []string {
	var links []string
	for _, cve := range r.CVEs {
		links = append(links, fmt.Sprintf("%s%s", NISTPrefix, cve))
	}
	// TODO(https://go.dev/issue/54488): check CVE status to determine which
	// link to include.
	if r.CVEMetadata != nil && r.CVEMetadata.ID != "" {
		links = append(links, fmt.Sprintf("%s%s", mitrePrefix, r.CVEMetadata.ID))
	}
	for _, ghsa := range r.GHSAs {
		// Don't duplicate GHSA link if it is the canonical advisory.
		if url := fmt.Sprintf("%s%s", ghsaURLPrefix, ghsa); url != r.Links.Advisory {
			links = append(links, url)
		}
	}
	return links
}

// AllLinks returns all reference links in the report.
func (r *Report) AllLinks() []string {
	var links []string
	if r.Links.PR != "" {
		links = append(links, r.Links.PR)
	}
	if r.Links.Commit != "" {
		links = append(links, r.Links.Commit)
	}
	return append(links, r.Links.Context...)
}

// AllSymbols returns both original and derived symbols.
func (a *Package) AllSymbols() []string {
	return append(append([]string(nil), a.Symbols...), a.DerivedSymbols...)
}

// Read reads a Report in YAML format from filename.
func Read(filename string) (_ *Report, err error) {
	defer derrors.Wrap(&err, "report.Read(%q)", filename)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	// Require that all fields in the file are in the struct.
	// This corresponds to v2's UnmarshalStrict.
	d.KnownFields(true)
	var r Report
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("yaml.Decode: %v", err)
	}
	return &r, nil
}

// Write writes r to filename in YAML format.
func (r *Report) Write(filename string) (err error) {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	err = r.encode(f)
	err2 := f.Close()
	if err == nil {
		err = err2
	}
	return err
}

// ToString encodes r to a YAML string.
func (r *Report) ToString() (string, error) {
	var b strings.Builder
	if err := r.encode(&b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (r *Report) encode(w io.Writer) error {
	e := yaml.NewEncoder(w)
	defer e.Close()
	e.SetIndent(4)
	return e.Encode(r)
}
