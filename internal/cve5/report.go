// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve5

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/version"
)

var (
	// The universal unique identifier for the Go Project CNA, which
	// needs to be included CVE JSON 5.0 records.
	GoOrgUUID = "1bb62c36-49e3-4200-9d77-64a1400537cc"
)

// FromReport creates a CVE in 5.0 format from a YAML report file.
func FromReport(r *report.Report) (_ *CVERecord, err error) {
	defer derrors.Wrap(&err, "FromReport(%q)", r.ID)

	if r.CVEMetadata == nil {
		return nil, errors.New("report missing cve_metadata section")
	}
	if r.CVEMetadata.ID == "" {
		return nil, errors.New("report missing CVE ID")
	}
	description := r.CVEMetadata.Description
	if description == "" {
		description = r.Description.String()
	}
	if r.CVEMetadata.CWE == "" {
		return nil, errors.New("report missing CWE")
	}

	c := &CNAPublishedContainer{
		ProviderMetadata: ProviderMetadata{
			OrgID: GoOrgUUID,
		},
		Title: report.RemoveNewlines(r.Summary.String()),
		Descriptions: []Description{
			{
				Lang:  "en",
				Value: report.RemoveNewlines(description),
			},
		},
		ProblemTypes: []ProblemType{
			{
				Descriptions: []ProblemTypeDescription{
					{
						Lang:        "en",
						Description: r.CVEMetadata.CWE,
					},
				},
			},
		},
	}

	for _, m := range r.Modules {
		versions, defaultStatus := versionsToVersionRanges(m.Versions)
		for _, p := range m.Packages {
			affected := Affected{
				Vendor:        report.Vendor(m.Module),
				Product:       p.Package,
				CollectionURL: "https://pkg.go.dev",
				PackageName:   p.Package,
				Versions:      versions,
				DefaultStatus: defaultStatus,
				Platforms:     p.GOOS,
			}
			for _, symbol := range p.AllSymbols() {
				affected.ProgramRoutines = append(affected.ProgramRoutines, ProgramRoutine{Name: symbol})
			}
			c.Affected = append(c.Affected, affected)
		}
	}

	for _, ref := range r.References {
		c.References = append(c.References, Reference{URL: ref.URL})
	}
	c.References = append(c.References, Reference{
		URL: idstr.GoAdvisory(r.ID),
	})
	for _, ref := range r.CVEMetadata.References {
		c.References = append(c.References, Reference{URL: ref})
	}

	for _, credit := range r.Credits {
		c.Credits = append(c.Credits, Credit{
			Lang:  "en",
			Value: credit,
		})
	}

	return &CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: Metadata{
			ID: r.CVEMetadata.ID,
		},
		Containers: Containers{
			CNAContainer: *c,
		},
	}, nil
}

const (
	typeSemver  = "semver"
	versionZero = "0"
)

func versionsToVersionRanges(vs report.Versions) ([]VersionRange, VersionStatus) {
	if len(vs) == 0 {
		// If there are no recorded versions affected, we assume all versions are affected.
		return nil, StatusAffected
	}

	var vrs []VersionRange

	// If there is no final fixed version, then the default status is
	// "affected" and we express the versions in terms of which ranges
	// are *unaffected*. This is due to the fact that the CVE schema
	// does not allow us to express a range as "version X.X.X and above are affected".
	if vs[len(vs)-1].Type != report.VersionTypeFixed {
		current := &VersionRange{}
		for _, vr := range vs {
			if vr.IsIntroduced() {
				if current.Introduced == "" {
					current.Introduced = versionZero
				}
				current.Fixed = Version(vr.Version)
				current.Status = StatusUnaffected
				current.VersionType = typeSemver
				vrs = append(vrs, *current)
				current = &VersionRange{}
			} else if vr.IsFixed() {
				current.Introduced = Version(vr.Version)
			}
		}
		return vrs, StatusAffected
	}

	// Otherwise, express the version ranges normally as affected ranges,
	// with a default status of "unaffected".
	var current *VersionRange
	for _, vr := range vs {
		if vr.IsIntroduced() {
			if current == nil {
				current = &VersionRange{
					Status:      StatusAffected,
					VersionType: typeSemver,
					Introduced:  Version(vr.Version),
				}
			}
		}
		if vr.IsFixed() {
			if current == nil {
				current = &VersionRange{
					Status:      StatusAffected,
					VersionType: typeSemver,
					Introduced:  versionZero,
				}
			}
			current.Fixed = Version(vr.Version)
			vrs = append(vrs, *current)
			current = nil
		}
	}

	return vrs, StatusUnaffected
}

var _ report.Source = &CVERecord{}

func (c *CVERecord) ToReport(modulePath string) *report.Report {
	return cve5ToReport(c, modulePath)
}

func (c *CVERecord) SourceID() string {
	return c.Metadata.ID
}

func (c *CVERecord) ReferenceURLs() []string {
	var result []string
	for _, r := range c.Containers.CNAContainer.References {
		result = append(result, r.URL)
	}
	return result
}

func cve5ToReport(c *CVERecord, modulePath string) *report.Report {
	cna := c.Containers.CNAContainer

	var description report.Description
	for _, d := range cna.Descriptions {
		if d.Lang == "en" {
			description += report.Description(d.Value + "\n")
		}
	}

	var credits []string
	for _, c := range cna.Credits {
		credits = append(credits, c.Value)
	}

	var refs []*report.Reference
	for _, ref := range c.Containers.CNAContainer.References {
		refs = append(refs, convertRef(ref))
	}

	r := &report.Report{
		Modules:     affectedToModules(cna.Affected, modulePath),
		Summary:     report.Summary(cna.Title),
		Description: description,
		Credits:     credits,
		References:  refs,
	}

	r.AddCVE(c.Metadata.ID, getCWE5(&cna), isGoCNA5(&cna))
	return r
}

func convertRef(ref Reference) *report.Reference {
	if t := typeFromTags(ref.Tags); t != osv.ReferenceTypeWeb {
		return &report.Reference{
			Type: t,
			URL:  ref.URL,
		}
	}
	return report.ReferenceFromUrl(ref.URL)
}

const (
	refTagIssue          = "issue-tracking"
	refTagMailingList    = "mailing-list"
	refTagPatch          = "patch"
	refTagReleaseNotes   = "release-notes"
	refTag3PAdvisory     = "third-party-advisory"
	refTagVendorAdvisory = "vendor-advisory"
	refTagVdbEntry       = "vdb-entry"
	refTagMedia          = "media-coverage"
	refTagTechnical      = "technical-description"
	refTagRelated        = "related"
	refTagGovt           = "government resource"
	refTagMitigation     = "mitigation"
	// uncategorized:
	// "broken-link"
	// "customer-entitlement"
	// "not-applicable"
	// "permissions-required"
	// "product"
	// "signature"
)

func tagToType(tag string) osv.ReferenceType {
	switch tag {
	case refTagVendorAdvisory:
		return osv.ReferenceTypeAdvisory
	case refTagIssue:
		return osv.ReferenceTypeReport
	case refTagPatch:
		return osv.ReferenceTypeFix
	}
	return defaultType
}

var order = []osv.ReferenceType{
	osv.ReferenceTypeAdvisory,
	osv.ReferenceTypeFix,
	osv.ReferenceTypeReport,
	osv.ReferenceTypeWeb,
}

var defaultType = osv.ReferenceTypeWeb

func bestType(types []osv.ReferenceType) osv.ReferenceType {
	if len(types) == 0 {
		return defaultType
	} else if len(types) == 1 {
		return types[0]
	}

	slices.SortStableFunc(types, func(a, b osv.ReferenceType) int {
		if a == b {
			return 0
		}
		for _, t := range order {
			if a == t {
				return -1
			}
			if b == t {
				return 1
			}
		}
		return 0
	})

	return types[0]
}

func typeFromTags(tags []string) osv.ReferenceType {
	var types []osv.ReferenceType
	for _, tag := range tags {
		if t := tagToType(tag); t != "" {
			types = append(types, t)
		}
	}
	return bestType(types)

}

func getCWE5(c *CNAPublishedContainer) string {
	if len(c.ProblemTypes) == 0 || len(c.ProblemTypes[0].Descriptions) == 0 {
		return ""
	}
	return c.ProblemTypes[0].Descriptions[0].Description
}

func isGoCNA5(c *CNAPublishedContainer) bool {
	return c.ProviderMetadata.OrgID == GoOrgUUID
}

func affectedToModules(as []Affected, modulePath string) []*report.Module {
	// Use a placeholder module if there is no information on
	// modules/packages in the CVE.
	if len(as) == 0 {
		return []*report.Module{{
			Module: modulePath,
		}}
	}

	var modules []*report.Module
	for _, a := range as {
		modules = append(modules, affectedToModule(&a, modulePath))
	}

	return modules
}

func affectedToModule(a *Affected, modulePath string) *report.Module {
	var pkgPath string
	isSet := func(s string) bool {
		const na = "n/a"
		return s != "" && s != na
	}
	switch {
	case isSet(a.PackageName):
		pkgPath = a.PackageName
	case isSet(a.Product):
		pkgPath = a.Product
	case isSet(a.Vendor):
		pkgPath = a.Vendor
	default:
		pkgPath = modulePath
	}

	// If the package path is just a suffix of the modulePath,
	// it is probably not useful.
	if strings.HasSuffix(modulePath, pkgPath) {
		pkgPath = modulePath
	}

	// If the package path doesn't have any slashes, it probably
	// is not useful.
	if !strings.Contains(pkgPath, "/") {
		pkgPath = modulePath
	}

	if stdlib.Contains(modulePath) && stdlib.Contains(pkgPath) {
		if strings.HasPrefix(pkgPath, stdlib.ToolchainModulePath) {
			modulePath = stdlib.ToolchainModulePath
		} else {
			modulePath = stdlib.ModulePath
		}
	}

	vs, uvs := convertVersions(a.Versions, a.DefaultStatus)

	// Add a package if we have any meaningful package-level data.
	var pkgs []*report.Package
	if pkgPath != modulePath || len(a.ProgramRoutines) != 0 || len(a.Platforms) != 0 {
		var symbols []string
		for _, s := range a.ProgramRoutines {
			symbols = append(symbols, s.Name)
		}
		pkgs = []*report.Package{
			{
				Package: pkgPath,
				Symbols: symbols,
				GOOS:    a.Platforms,
			},
		}
	}

	return &report.Module{
		Module:              modulePath,
		Versions:            vs,
		UnsupportedVersions: uvs,
		Packages:            pkgs,
	}
}

func convertVersions(vrs []VersionRange, defaultStatus VersionStatus) (vs report.Versions, uvs report.Versions) {
	for _, vr := range vrs {
		// Version ranges starting with "n/a" don't have any meaningful data.
		if vr.Introduced == "n/a" {
			continue
		}
		v, ok := toVersions(&vr, defaultStatus)
		if ok {
			vs = append(vs, v...)
			continue
		}
		uvs = append(uvs, toUnsupported(&vr, defaultStatus))
	}
	return vs, uvs
}

var (
	// Regex for matching version strings like "<= X, < Y".
	introducedFixedRE = regexp.MustCompile(`^>= (.+), < (.+)$`)
	// Regex for matching version strings like "< Y".
	fixedRE = regexp.MustCompile(`^< (.+)$`)
)

func toVersions(cvr *VersionRange, defaultStatus VersionStatus) (report.Versions, bool) {
	intro, fixed := version.TrimPrefix(string(cvr.Introduced)), version.TrimPrefix(string(cvr.Fixed))

	// Handle special cases where the info is not quite correctly encoded but
	// we can still figure out the intent.

	// Case one: introduced version is of the form "<= X, < Y".
	if m := introducedFixedRE.FindStringSubmatch(intro); len(m) == 3 {
		return report.Versions{
			report.Introduced(m[1]),
			report.Fixed(m[2]),
		}, true
	}

	// Case two: introduced version is of the form "< Y".
	if m := fixedRE.FindStringSubmatch(intro); len(m) == 2 {
		return report.Versions{
			report.Fixed(m[1]),
		}, true
	}

	// For now, don't attempt to fix any other messed up cases.
	if cvr.VersionType != typeSemver ||
		cvr.LessThanOrEqual != "" ||
		!version.IsValid(intro) ||
		!version.IsValid(fixed) ||
		cvr.Status != StatusAffected ||
		defaultStatus != StatusUnaffected {
		return nil, false
	}

	if intro == "0" {
		return report.Versions{
			report.Fixed(fixed),
		}, true
	}

	return report.Versions{
		report.Introduced(intro), report.Fixed(fixed),
	}, true
}

func toUnsupported(cvr *VersionRange, defaultStatus VersionStatus) *report.Version {
	var version string
	switch {
	case cvr.Fixed != "":
		version = fmt.Sprintf("%s from %s before %s", cvr.Status, cvr.Introduced, cvr.Fixed)
	case cvr.LessThanOrEqual != "":
		version = fmt.Sprintf("%s from %s to %s", cvr.Status, cvr.Introduced, cvr.LessThanOrEqual)
	default:
		version = fmt.Sprintf("%s at %s", cvr.Status, cvr.Introduced)
	}
	if defaultStatus != "" {
		version = fmt.Sprintf("%s (default: %s)", version, defaultStatus)
	}
	return &report.Version{
		Version: version,
		Type:    "cve_version_range",
	}
}
