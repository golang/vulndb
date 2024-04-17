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

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
	"gopkg.in/yaml.v3"
)

type VersionRange struct {
	Introduced string `yaml:"introduced,omitempty"`
	Fixed      string `yaml:"fixed,omitempty"`
}

type UnsupportedVersion struct {
	Version string `yaml:",omitempty"`
	Type    string `yaml:",omitempty"`
}

type Module struct {
	Module   string         `yaml:",omitempty"`
	Versions []VersionRange `yaml:",omitempty"`
	// Versions that are not known to the module proxy, but
	// that may be useful to display to humans.
	NonGoVersions []VersionRange `yaml:"non_go_versions,omitempty"`
	// Version types that exist in OSV, but we don't support.
	// These may be added when automatically creating a report,
	// but must be deleted in order to pass lint checks.
	UnsupportedVersions []UnsupportedVersion `yaml:"unsupported_versions,omitempty"`
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
	// Used to determine vulnerable symbols for a given module. If not populated,
	// the fix links found in the report's References field will be used.
	// Only auto-added if the -update flag is passed to vulnreport.
	FixLinks []string `yaml:"fix_links,omitempty"`
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
	// Symbols that may be considered vulnerable by automated tools,
	// but have been determined (by a human) to actually not be vulnerable.
	// For now, this field is respected only by the tool that finds derived
	// symbols, but is not published to OSV or elsewhere (so, for example,
	// govulncheck cannot consume it).
	ExcludedSymbols []string `yaml:"excluded_symbols,omitempty"`
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
	"LEGACY_FALSE_POSITIVE",
}

const excludedLabelPrefix = "excluded: "

func (er ExcludedReason) ToLabel() string {
	return fmt.Sprintf("%s%s", excludedLabelPrefix, string(er))
}

func FromLabel(label string) (ExcludedReason, bool) {
	pre, er, ok := strings.Cut(label, excludedLabelPrefix)
	if pre != "" {
		return "", false
	}
	return ExcludedReason(er), ok
}

// A Reference is a link to some external resource.
//
// For ease of typing, References are represented in the YAML as a
// single-element mapping of type to URL.
type Reference osv.Reference

func (r *Reference) MarshalYAML() (any, error) {
	return map[string]string{
		strings.ToLower(string(r.Type)): r.URL,
	}, nil
}

func (r *Reference) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode || len(n.Content) != 2 || n.Content[0].Kind != yaml.ScalarNode || n.Content[1].Kind != yaml.ScalarNode {
		return &yaml.TypeError{Errors: []string{
			fmt.Sprintf("line %d: report.Reference must contain a mapping with one value", n.Line),
		}}
	}
	r.Type = osv.ReferenceType(strings.ToUpper(n.Content[0].Value))
	r.URL = n.Content[1].Value
	return nil
}

// A Note is a note about the report.
// May be typed or untyped (with Type left blank).
type Note struct {
	Body string
	Type NoteType
}

type NoteType string

const (
	NoteTypeNone   NoteType = ""
	NoteTypeLint   NoteType = "LINT"
	NoteTypeFix    NoteType = "FIX"
	NoteTypeCreate NoteType = "CREATE"
)

func (n *Note) MarshalYAML() (any, error) {
	if n.Type == NoteTypeNone {
		return n.Body, nil
	}
	return map[string]string{
		strings.ToLower(string(n.Type)): n.Body,
	}, nil
}

func (n *Note) UnmarshalYAML(node *yaml.Node) error {
	// Handle untyped notes.
	if node.Kind == yaml.ScalarNode {
		n.Type = NoteTypeNone
		n.Body = node.Value
		return nil
	}

	// Handle typed notes.
	if node.Kind != yaml.MappingNode || len(node.Content) != 2 || node.Content[0].Kind != yaml.ScalarNode || node.Content[1].Kind != yaml.ScalarNode {
		return &yaml.TypeError{Errors: []string{
			fmt.Sprintf("line %d: typed Note must contain a mapping with one value", node.Line),
		}}
	}
	n.Type = NoteType(strings.ToUpper(node.Content[0].Value))
	n.Body = node.Content[1].Value
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
	Summary Summary `yaml:",omitempty"`

	// Description is the CVE description from an existing CVE. If we are
	// assigning a CVE ID ourselves, use CVEMetadata.Description instead.
	Description Description `yaml:",omitempty"`
	Published   time.Time   `yaml:",omitempty"`
	Withdrawn   *time.Time  `yaml:",omitempty"`

	// CVE are CVE IDs for existing CVEs.
	// If we are assigning a CVE ID ourselves, use CVEMetadata.ID instead.
	CVEs []string `yaml:",omitempty"`
	// GHSAs are the IDs of GitHub Security Advisories that match
	// the above CVEs.
	GHSAs []string `yaml:",omitempty"`

	// Aliases from other databases that we don't (yet) know about.
	// Not published to OSV.
	UnknownAliases []string `yaml:"unknown_aliases,omitempty"`

	// Related is a list of identifiers (e.g. CVEs or GHSAs)
	// that are related to, but are not direct aliases of, this report.
	Related []string `yaml:",omitempty"`

	Credits    []string     `yaml:",omitempty"`
	References []*Reference `yaml:",omitempty"`

	// CVEMetadata is used to capture CVE information when we want to assign a
	// CVE ourselves. If a CVE already exists for an issue, use the CVE field
	// to fill in the ID string.
	CVEMetadata *CVEMeta `yaml:"cve_metadata,omitempty"`

	// Notes about the report. This field is ignored when creating
	// OSV and CVE records. It can be used to document decisions made when
	// creating the report, outstanding issues, or anything else worth
	// mentioning.
	Notes []*Note `yaml:",omitempty"`

	// Metadata about how this report was generated.
	// Not published to OSV.
	SourceMeta *SourceMeta `yaml:"source,omitempty"`
}

const sourceGoTeam = "go-security-team"

type SourceMeta struct {
	// The ID (GHSA or CVE) of the original source of this report.
	// If created by a human, this is "go-security-team".
	ID string `yaml:",omitempty"`
	// The time the original auto-generated report was created.
	Created *time.Time `yaml:",omitempty"`
}

type Summary string
type Description string

func (s *Summary) String() string {
	return string(*s)
}

func (d *Description) String() string {
	return string(*d)
}

// GoCVE returns the CVE assigned to this report by the Go CNA,
// or the empty string if not applicable.
func (r *Report) GoCVE() string {
	if r.CVEMetadata == nil {
		return ""
	}
	return r.CVEMetadata.ID
}

// AllCVEs returns all CVE IDs for a report.
func (r *Report) AllCVEs() []string {
	all := slices.Clone(r.CVEs)
	if goCVE := r.GoCVE(); goCVE != "" {
		all = append(all, goCVE)
	}
	return all
}

// AllPkgs returns all affected packages in a given module.
func (m *Module) AllPackages() map[string]*Package {
	pkgs := make(map[string]*Package)
	for _, pkg := range m.Packages {
		pkgs[pkg.Package] = pkg
	}
	return pkgs
}

// CommitLinks returns all commit fix links in report.References
func (r *Report) CommitLinks() (links []string) {
	for _, ref := range r.References {
		if ref.Type == osv.ReferenceTypeFix {
			if strings.Contains(ref.URL, "commit") {
				links = append(links, ref.URL)
			}
		}
	}
	return links
}

// Aliases returns all aliases (e.g., CVEs, GHSAs) for a report.
func (r *Report) Aliases() []string {
	return append(r.AllCVEs(), r.GHSAs...)
}

// AddAliases adds any GHSAs and CVEs in aliases that were not
// already present to the report.
func (r *Report) AddAliases(aliases []string) (added int) {
	original := make(map[string]bool)
	for _, alias := range r.Aliases() {
		original[alias] = true
	}

	for _, alias := range aliases {
		switch {
		case original[alias]:
			continue
		case ghsa.IsGHSA(alias):
			r.GHSAs = append(r.GHSAs, alias)
		case cveschema5.IsCVE(alias):
			r.CVEs = append(r.CVEs, alias)
		default:
			continue // skip aliases that are not CVEs or GHSAs
		}
		added++
	}

	if added > 0 {
		slices.Sort(r.GHSAs)
		slices.Sort(r.CVEs)
	}

	return added
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
	m := reportFilepathRegexp.FindStringSubmatch(filepath.ToSlash(path))
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
func ReadAndLint(filename string, pc *proxy.Client) (r *Report, err error) {
	r, err = Read(filename)
	if err != nil {
		return nil, err
	}
	if err := r.CheckFilename(filename); err != nil {
		return nil, err
	}
	if lints := r.Lint(pc); len(lints) > 0 {
		return nil, fmt.Errorf("%v: contains lint warnings:\n%s", filename, strings.Join(lints, "\n"))
	}
	return r, nil
}

func (r *Report) YAMLFilename() (string, error) {
	if r.ID == "" {
		return "", errors.New("report has no ID")
	}
	return filepath.Join(dataFolder, r.folder(), r.ID+".yaml"), nil
}

func (r *Report) folder() string {
	if r.IsExcluded() {
		return excludedFolder
	}
	return reportsFolder
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
