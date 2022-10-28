// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/derrors"
)

// TODO(https://go.dev/issues/53256): Add a function to convert from
// cveschema5.CVERecord to Report.

// The universal unique identifier for the Go Project CNA, which
// needs to be included CVE JSON 5.0 records.
var GoOrgUUID = "1bb62c36-49e3-4200-9d77-64a1400537cc"

// ToCVE5 creates a CVE in 5.0 format from a YAML report file.
func ToCVE5(reportPath string) (_ *cveschema5.CVERecord, err error) {
	defer derrors.Wrap(&err, "report.ToCVERecord(%q)", reportPath)

	r, err := Read(reportPath)
	if err != nil {
		return nil, err
	}

	if lints := r.Lint(reportPath); len(lints) > 0 {
		return nil, fmt.Errorf("report has outstanding lint errors:\n  %v", strings.Join(lints, "\n  "))
	}
	if len(r.CVEs) > 0 {
		return nil, errors.New("report has CVE ID is wrong section (should be in cve_metadata for self-issued CVEs)")
	}
	if r.CVEMetadata == nil {
		return nil, errors.New("report missing cve_metadata section")
	}
	if r.CVEMetadata.ID == "" {
		return nil, errors.New("report missing CVE ID")
	}
	description := r.CVEMetadata.Description
	if description == "" {
		description = r.Description
	}
	if r.CVEMetadata.CWE == "" {
		return nil, errors.New("report missing CWE")
	}

	c := &cveschema5.CNAPublishedContainer{
		ProviderMetadata: cveschema5.ProviderMetadata{
			OrgID: GoOrgUUID,
		},
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
		versions := versionRangeToVersionRange(m.Versions)
		defaultStatus := cveschema5.StatusUnaffected
		if len(versions) == 0 {
			// If there are no recorded versions affected, we assume all versions are affected.
			defaultStatus = cveschema5.StatusAffected
		}
		for _, p := range m.Packages {
			affected := cveschema5.Affected{
				Vendor:        getVendor(m.Module),
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
	advisoryLink := GetGoAdvisoryLink(GetGoIDFromFilename(reportPath))
	c.References = append(c.References, cveschema5.Reference{URL: advisoryLink})

	if r.Credit != "" {
		c.Credits = []cveschema5.Credit{
			{
				Lang:  "en",
				Value: r.Credit,
			},
		}
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

func versionRangeToVersionRange(versions []VersionRange) []cveschema5.VersionRange {
	var cveVRs []cveschema5.VersionRange
	for _, vr := range versions {
		cveVR := cveschema5.VersionRange{
			Status:      cveschema5.StatusAffected,
			VersionType: "semver",
		}
		if vr.Introduced != "" {
			cveVR.Introduced = cveschema5.Version(vr.Introduced)
		} else {
			cveVR.Introduced = "0"
		}
		if vr.Fixed != "" {
			cveVR.Fixed = cveschema5.Version(vr.Fixed)
		}
		cveVRs = append(cveVRs, cveVR)
	}
	return cveVRs
}
