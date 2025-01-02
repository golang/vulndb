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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/stdlib"
	"gopkg.in/yaml.v3"
)

type Module struct {
	Module   string   `yaml:",omitempty"`
	Versions Versions `yaml:",omitempty"`
	// Versions that are not known to the module proxy, but
	// that may be useful to display to humans.
	NonGoVersions Versions `yaml:"non_go_versions,omitempty"`
	// Version types that exist in OSV, but we don't support.
	// These may be added when automatically creating a report,
	// but must be deleted in order to pass lint checks.
	UnsupportedVersions Versions `yaml:"unsupported_versions,omitempty"`
	// Known-vulnerable version, to use when performing static analysis or
	// other techniques on a vulnerable version of the package.
	//
	// In general, we want to use the most recent vulnerable version of
	// the package. Determining this programmatically is difficult, especially
	// for packages without tagged versions, so we specify it manually here.
	VulnerableAt *Version `yaml:"vulnerable_at,omitempty"`
	// Additional list of module@version to require when performing static analysis.
	// It is rare that we need to specify this.
	VulnerableAtRequires []string   `yaml:"vulnerable_at_requires,omitempty"`
	Packages             []*Package `yaml:",omitempty"`
	// Used to determine vulnerable symbols for a given module. If not populated,
	// the fix links found in the report's References field will be used.
	// Only auto-added if the -update flag is passed to vulnreport.
	FixLinks []string `yaml:"fix_links,omitempty"`
	// Do not lint this module.
	// Only for use in exceptional circumstances, such as when a malicious
	// module has been deleted from the proxy entirely.
	SkipLint bool `yaml:"skip_lint,omitempty"`
}

type Version struct {
	Version string      `yaml:",omitempty"`
	Type    VersionType `yaml:",omitempty"`
}

type VersionType string

const (
	VersionTypeIntroduced   = "introduced"
	VersionTypeFixed        = "fixed"
	VersionTypeVulnerableAt = "vulnerable_at"
)

func Introduced(v string) *Version {
	return &Version{Version: v, Type: VersionTypeIntroduced}
}

func Fixed(v string) *Version {
	return &Version{Version: v, Type: VersionTypeFixed}
}

type VulnerableAtVersion Version

func VulnerableAt(v string) *Version {
	return &Version{Version: v, Type: VersionTypeVulnerableAt}
}

func (v *Version) IsIntroduced() bool {
	return v.Type == VersionTypeIntroduced
}

func (v *Version) IsFixed() bool {
	return v.Type == VersionTypeFixed
}

func (v *Version) MarshalYAML() (any, error) {
	return v.Version, nil
}

func (v *Version) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: report.Version must be a scalar node", n.Line)
	}
	v.Type = VersionTypeVulnerableAt
	v.Version = n.Value
	return nil
}

type Versions []*Version

func (vs Versions) MarshalYAML() (any, error) {
	result := make([]map[string]string, len(vs))
	for i, v := range vs {
		result[i] = map[string]string{
			strings.ToLower(string(v.Type)): v.Version,
		}
	}
	return result, nil
}

func (vs *Versions) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return &yaml.TypeError{Errors: []string{
			fmt.Sprintf("line %d: report.Versions must be a sequence node (got %#v)", n.Line, n),
		}}
	}

	*vs = make(Versions, 0)
	for _, vn := range n.Content {
		// Support the old way of encoding introduced/fixed versions.
		if vn.Kind == yaml.MappingNode && len(vn.Content) == 4 {
			// Format is
			//  	- introduced: v.v.v
			//        fixed: v.v.v
			if VersionType(vn.Content[0].Value) == VersionTypeIntroduced {
				*vs = append(*vs, &Version{
					Type:    VersionType(vn.Content[0].Value),
					Version: vn.Content[1].Value,
				},
					&Version{
						Type:    VersionType(vn.Content[2].Value),
						Version: vn.Content[3].Value,
					},
				)
				continue
			}

			// Format is
			//  	- version: v.v.v
			//        type: t
			*vs = append(*vs, &Version{
				Type:    VersionType(vn.Content[3].Value),
				Version: vn.Content[1].Value,
			})
			continue
		}
		if vn.Kind != yaml.MappingNode || len(vn.Content) != 2 || vn.Content[0].Kind != yaml.ScalarNode || vn.Content[1].Kind != yaml.ScalarNode {
			return &yaml.TypeError{Errors: []string{
				fmt.Sprintf("line %d: report.Version must contain a mapping with one value (got %#v)", vn.Line, vn),
			}}
		}
		*vs = append(*vs, &Version{
			Type:    VersionType(vn.Content[0].Value),
			Version: vn.Content[1].Value,
		})
	}

	return nil
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
	// Reason the package's symbols are already considered fixed and should not
	// be checked or automatically updated.
	SkipFixSymbols string `yaml:"skip_fix,omitempty"`
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

// ExcludedType is the reason a report is excluded from the database.
//
// It must be one of the values in ExcludedTypes.
type ExcludedType string

const (
	ExcludedNotImportable         ExcludedType = "NOT_IMPORTABLE"
	ExcludedNotGoCode             ExcludedType = "NOT_GO_CODE"
	ExcludedNotAVulnerability     ExcludedType = "NOT_A_VULNERABILITY"
	ExcludedEffectivelyPrivate    ExcludedType = "EFFECTIVELY_PRIVATE"
	ExcludedDependentVulnerabilty ExcludedType = "DEPENDENT_VULNERABILITY"
	ExcludedLegacyFalsePositive   ExcludedType = "LEGACY_FALSE_POSITIVE"
	ExcludedWithdrawn             ExcludedType = "WITHDRAWN"
)

// ExcludedTypes are the set of reasons a report may be excluded from the database.
// These are described in detail at
// https://go.googlesource.com/vulndb/+/refs/heads/master/doc/format.md.
var ExcludedTypes = []ExcludedType{
	ExcludedNotImportable,
	ExcludedNotGoCode,
	ExcludedNotAVulnerability,
	ExcludedEffectivelyPrivate,
	ExcludedDependentVulnerabilty,
	ExcludedLegacyFalsePositive,
	ExcludedWithdrawn,
}

func (e *ExcludedType) IsValid() bool {
	return slices.Contains(ExcludedTypes, *e)
}

func ToExcludedType(s string) (ExcludedType, bool) {
	e := ExcludedType(s)
	if !e.IsValid() {
		return "", false
	}
	return e, true
}

const excludedLabelPrefix = "excluded: "

func (e ExcludedType) ToLabel() string {
	return fmt.Sprintf("%s%s", excludedLabelPrefix, string(e))
}

func FromLabel(label string) (ExcludedType, bool) {
	pre, er, ok := strings.Cut(label, excludedLabelPrefix)
	if pre != "" || !ok {
		return "", false
	}
	return ToExcludedType(er)
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
	Excluded ExcludedType `yaml:",omitempty"`

	Modules []*Module `yaml:",omitempty"`

	// Summary is a short phrase describing the vulnerability.
	Summary Summary `yaml:",omitempty"`

	// Description is the CVE description from an existing CVE. If we are
	// assigning a CVE ID ourselves, use CVEMetadata.Description instead.
	Description Description `yaml:",omitempty"`
	Published   time.Time   `yaml:",omitempty"`
	Withdrawn   *osv.Time   `yaml:",omitempty"`

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

	ReviewStatus ReviewStatus `yaml:"review_status,omitempty"`
	// Allow this report to be UNREVIEWED regardless of it's modules'
	// priorities.
	UnreviewedOK bool `yaml:"unreviewed_ok,omitempty"`

	// (For unexcluded reports) The reason this report was previously
	// excluded. Not published to OSV.
	Unexcluded ExcludedType `yaml:"unexcluded,omitempty"`
}

type ReviewStatus int

const (
	unknownReviewStatus ReviewStatus = iota
	Reviewed
	Unreviewed
	NeedsReview
)

type statusMapping struct {
	name string
	osv  osv.ReviewStatus
}

var statuses = []statusMapping{
	Reviewed:    {"REVIEWED", osv.ReviewStatusReviewed},
	Unreviewed:  {"UNREVIEWED", osv.ReviewStatusUnreviewed},
	NeedsReview: {"NEEDS_REVIEW", osv.ReviewStatusUnreviewed},
}

func reviewStatusValues() []string {
	var vals []string
	for _, v := range statuses[Reviewed:] {
		vals = append(vals, v.name)
	}
	return vals
}

func (r ReviewStatus) String() string {
	return statuses[r].name
}

func (r ReviewStatus) ToOSV() osv.ReviewStatus {
	return statuses[r].osv
}

func ToReviewStatus(s string) (ReviewStatus, bool) {
	for stat, v := range statuses {
		if s == v.name {
			return ReviewStatus(stat), true
		}
	}
	return 0, false
}

func (r ReviewStatus) IsValid() bool {
	return r >= Reviewed && int(r) < len(statuses)
}

func (r ReviewStatus) MarshalYAML() (any, error) {
	if !r.IsValid() {
		return nil, fmt.Errorf("MarshalYAML: unrecognized review status: %s", r)
	}
	return r.String(), nil
}

func (r *ReviewStatus) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		v := node.Value
		if rs, ok := ToReviewStatus(v); ok {
			*r = rs
			return nil
		}
		return fmt.Errorf("UnmarshalYAML: unrecognized review status: %s", v)
	}
	return fmt.Errorf("UnmarshalYAML: incorrect node type %v", node.Kind)
}

const sourceGoTeam = "go-security-team"

type SourceMeta struct {
	// The ID (GHSA or CVE) of the original source of this report.
	// If created by a human, this is "go-security-team".
	ID string `yaml:",omitempty"`
	// The time the auto-generated report was created (or re-generated
	// from source).
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

// AllPackages returns all affected packages in a given module.
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
		case idstr.IsGHSA(alias):
			r.GHSAs = append(r.GHSAs, alias)
		case idstr.IsCVE(alias):
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

// GoID returns the Go ID from the given filename, assuming the filename
// is of the form "*/<goID>.<ext>".
func GoID(filename string) string {
	return strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
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
	return decodeStrict(f)
}

func decodeStrict(f io.Reader) (*Report, error) {
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

func ReadStrict(fsys fs.FS, filename string) (*Report, error) {
	r, err := readFS(fsys, filename)
	if err != nil {
		return nil, err
	}
	if err := r.CheckFilename(filename); err != nil {
		return nil, err
	}
	return r, nil
}

func readFS(fsys fs.FS, filename string) (*Report, error) {
	f, err := fsys.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeStrict(f)
}

func (r *Report) YAMLFilename() (string, error) {
	if r.ID == "" {
		return "", errors.New("report has no ID")
	}
	return filepath.Join(dataFolder, r.folder(), r.ID+".yaml"), nil
}

func (r *Report) CVEFilename() string {
	return filepath.Join(cve5Dir, r.ID+".json")
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
	err = r.Encode(f)
	err2 := f.Close()
	if err == nil {
		err = err2
	}
	return err
}

// ToString encodes r to a YAML string.
func (r *Report) ToString() (string, error) {
	var b strings.Builder
	if err := r.Encode(&b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (r *Report) Encode(w io.Writer) error {
	e := yaml.NewEncoder(w)
	defer e.Close()
	e.SetIndent(4)
	return e.Encode(r)
}

func Vendor(modulePath string) string {
	switch modulePath {
	case stdlib.ModulePath:
		return "Go standard library"
	case stdlib.ToolchainModulePath:
		return "Go toolchain"
	default:
		return modulePath
	}
}

func (r *Report) AddCVE(cveID, cwe string, isGoCNA bool) {
	if isGoCNA {
		r.CVEMetadata = &CVEMeta{
			ID:  cveID,
			CWE: cwe,
		}
		return
	}
	r.CVEs = append(r.CVEs, cveID)
}

// RemoveNewlines removes leading and trailing space characters and
// replaces inner newlines with spaces.
func RemoveNewlines(s string) string {
	newlines := regexp.MustCompile(`\n+`)
	return newlines.ReplaceAllString(strings.TrimSpace(s), " ")
}
