// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package report contains functionality for parsing and linting YAML reports
// in reports/.
package report

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
	"gopkg.in/yaml.v3"
)

type VersionRange struct {
	Introduced string `yaml:"introduced,omitempty"`
	Fixed      string `yaml:"fixed,omitempty"`
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
	VulnerableAt string `yaml:"vulnerable_at,omitempty"`
	// Additional list of module@version to require when performing static analysis.
	// It is rare that we need to specify this.
	VulnerableAtRequires []string   `yaml:"vulnerable_at_requires,omitempty"`
	Packages             []*Package `yaml:",omitempty"`
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
	// Reason the package is already considered fixed and should not be automatically updated.
	SkipFix string `yaml:"skip_fix,omitempty"`
}

type CVEMeta struct {
	ID          string `yaml:",omitempty"`
	CWE         string `yaml:",omitempty"`
	Description string `yaml:",omitempty"`
	// Additional references that should be included in the CVE record
	// but not the OSV. This is used to preserve references that have been
	// added to a CVE by the CVE program that the Go team does not want
	// to display via OSV. An example that uses this is GO-2022-0476.
	References []string `yaml:",omitempty"`
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

// A Reference is a link to some external resource.
//
// For ease of typing, References are represented in the YAML as a
// single-element mapping of type to URL.
type Reference osv.Reference

func (r *Reference) MarshalYAML() (interface{}, error) {
	return map[string]string{
		strings.ToLower(string(r.Type)): r.URL,
	}, nil
}

func (r *Reference) UnmarshalYAML(n *yaml.Node) (err error) {
	if n.Kind != yaml.MappingNode || len(n.Content) != 2 || n.Content[0].Kind != yaml.ScalarNode || n.Content[1].Kind != yaml.ScalarNode {
		return &yaml.TypeError{Errors: []string{
			fmt.Sprintf("line %d: report.Reference must contain a mapping with one value", n.Line),
		}}
	}
	r.Type = osv.ReferenceType(strings.ToUpper(n.Content[0].Value))
	r.URL = n.Content[1].Value
	return nil
}

// Report represents a vulnerability report in the vulndb.
// Remember to update doc/format.md when this structure changes.
type Report struct {
	ID string `yaml:",omitempty"`

	// Excluded indicates an excluded report.
	Excluded ExcludedReason `yaml:",omitempty"`

	Modules []*Module `yaml:",omitempty"`

	// Summary is a short phrase describing the vulnerability.
	Summary string `yaml:",omitempty"`

	// Description is the CVE description from an existing CVE. If we are
	// assigning a CVE ID ourselves, use CVEMetadata.Description instead.
	Description string     `yaml:",omitempty"`
	Published   time.Time  `yaml:",omitempty"`
	Withdrawn   *time.Time `yaml:",omitempty"`

	// CVE are CVE IDs for existing CVEs.
	// If we are assigning a CVE ID ourselves, use CVEMetadata.ID instead.
	CVEs []string `yaml:",omitempty"`
	// GHSAs are the IDs of GitHub Security Advisories that match
	// the above CVEs.
	GHSAs []string `yaml:",omitempty"`

	Credits    []string     `yaml:",omitempty"`
	References []*Reference `yaml:",omitempty"`

	// CVEMetadata is used to capture CVE information when we want to assign a
	// CVE ourselves. If a CVE already exists for an issue, use the CVE field
	// to fill in the ID string.
	CVEMetadata *CVEMeta `yaml:"cve_metadata,omitempty"`
}

// AllCVEs returns all CVE IDs for a report, including any in cve_metadata.
func (r *Report) AllCVEs() []string {
	if r.CVEMetadata != nil {
		return []string{r.CVEMetadata.ID}
	}
	return r.CVEs
}

// Aliases returns all aliases (e.g., CVEs, GHSAs) for a report.
func (r *Report) Aliases() []string {
	return append(r.AllCVEs(), r.GHSAs...)
}

const (
	NISTPrefix    = "https://nvd.nist.gov/vuln/detail/"
	ghsaURLPrefix = "https://github.com/advisories/"
	goURLPrefix   = "https://pkg.go.dev/vuln/"
)

// GoID returns the Go ID from the given filename, assuming the filename
// is of the form "*/<goID>.<ext>".
func GoID(filename string) string {
	return strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
}

func GoAdvisory(id string) string {
	return fmt.Sprintf("%s%s", goURLPrefix, id)
}

// AllSymbols returns both original and derived symbols.
func (a *Package) AllSymbols() []string {
	return append(append([]string(nil), a.Symbols...), a.DerivedSymbols...)
}

var reportFilepathRegexp = regexp.MustCompile(`^(data/\w+)/(GO-\d\d\d\d-0*(\d+)\.yaml)$`)

func ParseFilepath(path string) (folder, filename string, issueID int, err error) {
	m := reportFilepathRegexp.FindStringSubmatch(path)
	if len(m) != 4 {
		return "", "", 0, fmt.Errorf("%v: not a report filepath", path)
	}
	folder = m[1]
	filename = m[2]
	issueID, err = strconv.Atoi(m[3])
	if err != nil {
		return "", "", 0, err
	}
	return
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

// ReadAndLint reads a Report in YAML format from filename,
// lints the Report, and errors if there are any lint warnings.
func ReadAndLint(filename string) (r *Report, err error) {
	r, err = Read(filename)
	if err != nil {
		return nil, err
	}
	if err := r.CheckFilename(filename); err != nil {
		return nil, err
	}
	if lints := r.Lint(); len(lints) > 0 {
		return nil, fmt.Errorf("%v: contains lint warnings:\n%s", filename, strings.Join(lints, "\n"))
	}
	return r, nil
}

func (r *Report) YAMLFilename() (string, error) {
	dir := YAMLDir
	if r.Excluded != "" {
		dir = ExcludedDir
	}
	if r.ID == "" {
		return "", errors.New("report has no ID")
	}
	return filepath.Join(dir, r.ID+".yaml"), nil
}

// Write writes r to filename in YAML format.
func (r *Report) Write(filename string) (err error) {
	defer derrors.Wrap(&err, "Write(%s)", filename)

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
