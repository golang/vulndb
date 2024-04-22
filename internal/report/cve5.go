// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/vulndb/internal/cveclient"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/version"
)

var (
	// The universal unique identifier for the Go Project CNA, which
	// needs to be included CVE JSON 5.0 records.
	GoOrgUUID = "1bb62c36-49e3-4200-9d77-64a1400537cc"

	cve5Dir = "data/cve/v5"
)

// ToCVE5 creates a CVE in 5.0 format from a YAML report file.
func (r *Report) ToCVE5() (_ *cveschema5.CVERecord, err error) {
	defer derrors.Wrap(&err, "ToCVERecord(%q)", r.ID)

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

	c := &cveschema5.CNAPublishedContainer{
		ProviderMetadata: cveschema5.ProviderMetadata{
			OrgID: GoOrgUUID,
		},
		Title: removeNewlines(r.Summary.String()),
		Descriptions: []cveschema5.Description{
			{
				Lang:  "en",
				Value: removeNewlines(description),
			},
		},
		ProblemTypes: []cveschema5.ProblemType{
			{
				Descriptions: []cveschema5.ProblemTypeDescription{
					{
						Lang:        "en",
						Description: r.CVEMetadata.CWE,
					},
				},
			},
		},
	}

	for _, m := range r.Modules {
		versions, defaultStatus := versionRangeToVersionRange(m.Versions)
		for _, p := range m.Packages {
			affected := cveschema5.Affected{
				Vendor:        vendor(m.Module),
				Product:       p.Package,
				CollectionURL: "https://pkg.go.dev",
				PackageName:   p.Package,
				Versions:      versions,
				DefaultStatus: defaultStatus,
				Platforms:     p.GOOS,
			}
			for _, symbol := range p.AllSymbols() {
				affected.ProgramRoutines = append(affected.ProgramRoutines, cveschema5.ProgramRoutine{Name: symbol})
			}
			c.Affected = append(c.Affected, affected)
		}
	}

	for _, ref := range r.References {
		c.References = append(c.References, cveschema5.Reference{URL: ref.URL})
	}
	c.References = append(c.References, cveschema5.Reference{
		URL: GoAdvisory(r.ID),
	})
	for _, ref := range r.CVEMetadata.References {
		c.References = append(c.References, cveschema5.Reference{URL: ref})
	}

	for _, credit := range r.Credits {
		c.Credits = append(c.Credits, cveschema5.Credit{
			Lang:  "en",
			Value: credit,
		})
	}

	return &cveschema5.CVERecord{
		DataType:    "CVE_RECORD",
		DataVersion: "5.0",
		Metadata: cveschema5.Metadata{
			ID: r.CVEMetadata.ID,
		},
		Containers: cveschema5.Containers{
			CNAContainer: *c,
		},
	}, nil
}

func (r *Report) CVEFilename() string {
	return filepath.Join(cve5Dir, r.ID+".json")
}

const (
	typeSemver  = "semver"
	versionZero = "0"
)

func versionRangeToVersionRange(versions []VersionRange) ([]cveschema5.VersionRange, cveschema5.VersionStatus) {
	if len(versions) == 0 {
		// If there are no recorded versions affected, we assume all versions are affected.
		return nil, cveschema5.StatusAffected
	}

	var cveVRs []cveschema5.VersionRange

	// If there is no final fixed version, then the default status is
	// "affected" and we express the versions in terms of which ranges
	// are *unaffected*. This is due to the fact that the CVE schema
	// does not allow us to express a range as "version X.X.X and above are affected".
	if versions[len(versions)-1].Fixed == "" {
		current := &cveschema5.VersionRange{}
		for _, vr := range versions {
			if vr.Introduced != "" {
				if current.Introduced == "" {
					current.Introduced = versionZero
				}
				current.Fixed = cveschema5.Version(vr.Introduced)
				current.Status = cveschema5.StatusUnaffected
				current.VersionType = typeSemver
				cveVRs = append(cveVRs, *current)
				current = &cveschema5.VersionRange{}
			}
			if vr.Fixed != "" {
				current.Introduced = cveschema5.Version(vr.Fixed)
			}
		}
		return cveVRs, cveschema5.StatusAffected
	}

	// Otherwise, express the version ranges normally as affected ranges,
	// with a default status of "unaffected".
	for _, vr := range versions {
		cveVR := cveschema5.VersionRange{
			Status:      cveschema5.StatusAffected,
			VersionType: typeSemver,
		}
		if vr.Introduced != "" {
			cveVR.Introduced = cveschema5.Version(vr.Introduced)
		} else {
			cveVR.Introduced = versionZero
		}
		if vr.Fixed != "" {
			cveVR.Fixed = cveschema5.Version(vr.Fixed)
		}
		cveVRs = append(cveVRs, cveVR)
	}

	return cveVRs, cveschema5.StatusUnaffected
}

type cve5 struct {
	*cveschema5.CVERecord
}

var _ Source = &cve5{}

func ToCVE5(c *cveschema5.CVERecord) Source {
	return &cve5{CVERecord: c}
}

func (c *cve5) ToReport(modulePath string) *Report {
	return cve5ToReport(c.CVERecord, modulePath)
}

func (c *cve5) SourceID() string {
	return c.Metadata.ID
}

type cve5Fetcher struct{}

func CVE5Fetcher() Fetcher {
	return &cve5Fetcher{}
}

func (*cve5Fetcher) Fetch(ctx context.Context, id string) (Source, error) {
	cve, err := cveclient.Fetch(id)
	if err != nil {
		return nil, err
	}
	return &cve5{CVERecord: cve}, nil
}

func cve5ToReport(c *cveschema5.CVERecord, modulePath string) *Report {
	cna := c.Containers.CNAContainer

	var description Description
	for _, d := range cna.Descriptions {
		if d.Lang == "en" {
			description += Description(d.Value + "\n")
		}
	}

	var credits []string
	for _, c := range cna.Credits {
		credits = append(credits, c.Value)
	}

	var refs []*Reference
	for _, ref := range c.Containers.CNAContainer.References {
		refs = append(refs, referenceFromUrl(ref.URL))
	}

	r := &Report{
		Modules:     affectedToModules(cna.Affected, modulePath),
		Summary:     Summary(cna.Title),
		Description: description,
		Credits:     credits,
		References:  refs,
	}

	r.addCVE(c.Metadata.ID, getCWE5(&cna), isGoCNA5(&cna))
	return r
}

func getCWE5(c *cveschema5.CNAPublishedContainer) string {
	if len(c.ProblemTypes) == 0 || len(c.ProblemTypes[0].Descriptions) == 0 {
		return ""
	}
	return c.ProblemTypes[0].Descriptions[0].Description
}

func isGoCNA5(c *cveschema5.CNAPublishedContainer) bool {
	return c.ProviderMetadata.OrgID == GoOrgUUID
}

func affectedToModules(as []cveschema5.Affected, modulePath string) []*Module {
	// Use a placeholder module if there is no information on
	// modules/packages in the CVE.
	if len(as) == 0 {
		return []*Module{{
			Module: modulePath,
		}}
	}

	var modules []*Module
	for _, a := range as {
		modules = append(modules, affectedToModule(&a, modulePath))
	}

	return modules
}

func affectedToModule(a *cveschema5.Affected, modulePath string) *Module {
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

	if stdlib.Contains(pkgPath) {
		if strings.HasPrefix(pkgPath, stdlib.ToolchainModulePath) {
			modulePath = stdlib.ToolchainModulePath
		} else {
			modulePath = stdlib.ModulePath
		}
	}

	var symbols []string
	for _, s := range a.ProgramRoutines {
		symbols = append(symbols, s.Name)
	}

	vs, uvs := convertVersions(a.Versions, a.DefaultStatus)

	return &Module{
		Module:              modulePath,
		Versions:            vs,
		UnsupportedVersions: uvs,
		Packages: []*Package{
			{
				Package: pkgPath,
				Symbols: symbols,
				GOOS:    a.Platforms,
			},
		},
	}
}

func convertVersions(vrs []cveschema5.VersionRange, defaultStatus cveschema5.VersionStatus) (vs []VersionRange, uvs []UnsupportedVersion) {
	for _, vr := range vrs {
		// Version ranges starting with "n/a" don't have any meaningful data.
		if vr.Introduced == "n/a" {
			continue
		}
		v, ok := toVersionRange(&vr, defaultStatus)
		if ok {
			vs = append(vs, *v)
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

func toVersionRange(cvr *cveschema5.VersionRange, defaultStatus cveschema5.VersionStatus) (*VersionRange, bool) {
	// Handle special cases where the info is not quite correctly encoded but
	// we can still figure out the intent.

	// Case one: introduced version is of the form "<= X, < Y".
	if m := introducedFixedRE.FindStringSubmatch(string(cvr.Introduced)); len(m) == 3 {
		return &VersionRange{
			Introduced: m[1],
			Fixed:      m[2],
		}, true
	}

	// Case two: introduced version is of the form "< Y".
	if m := fixedRE.FindStringSubmatch(string(cvr.Introduced)); len(m) == 2 {
		return &VersionRange{
			Fixed: m[1],
		}, true
	}

	// For now, don't attempt to fix any other messed up cases.
	if cvr.VersionType != typeSemver ||
		cvr.LessThanOrEqual != "" ||
		!version.IsValid(string(cvr.Introduced)) ||
		!version.IsValid(string(cvr.Fixed)) ||
		cvr.Status != cveschema5.StatusAffected ||
		defaultStatus != cveschema5.StatusUnaffected {
		return nil, false
	}

	introduced := string(cvr.Introduced)
	if introduced == "0" {
		introduced = ""
	}

	return &VersionRange{
		Introduced: introduced,
		Fixed:      string(cvr.Fixed),
	}, true
}

func toUnsupported(cvr *cveschema5.VersionRange, defaultStatus cveschema5.VersionStatus) UnsupportedVersion {
	var version string
	switch {
	case cvr.Fixed != "":
		version = fmt.Sprintf("%s from %s before %s", cvr.Status, cvr.Introduced, cvr.Fixed)
	case cvr.LessThanOrEqual != "":
		version = fmt.Sprintf("%s from %s to %s", cvr.Status, cvr.Introduced, cvr.Fixed)
	default:
		version = fmt.Sprintf("%s at %s", cvr.Status, cvr.Introduced)
	}
	if defaultStatus != "" {
		version = fmt.Sprintf("%s (default: %s)", version, defaultStatus)
	}
	return UnsupportedVersion{
		Version: version,
		Type:    "cve_version_range",
	}
}
