// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"path/filepath"

	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/derrors"
)

// TODO(https://go.dev/issues/53256): Add a function to convert from
// cveschema5.CVERecord to Report.

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
