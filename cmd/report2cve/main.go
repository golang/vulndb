// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/vulndb/internal"
	"golang.org/x/vulndb/internal/report"
	"gopkg.in/yaml.v2"
)

func fromReport(r *report.Report) (*internal.CVE, error) {
	if r.CVE != "" {
		return nil, errors.New("report has CVE ID is wrong section (should be in cve_metadata for self-issued CVEs)")
	}
	if r.CVEMetadata == nil {
		return nil, errors.New("report missing cve_metadata section")
	}
	if r.CVEMetadata.ID == "" {
		return nil, errors.New("report missing CVE ID")
	}

	c := &internal.CVE{
		DataType:    "CVE",
		DataFormat:  "MITRE",
		DataVersion: "4.0",
		CVEDataMeta: internal.CVEDataMeta{
			ID:       r.CVEMetadata.ID,
			ASSIGNER: "security@golang.org",
			STATE:    "PUBLIC",
		},

		Description: internal.Description{
			DescriptionData: []internal.LangString{
				{
					Lang:  "eng",
					Value: strings.TrimSuffix(r.CVEMetadata.Description, "\n"),
				},
			},
		},

		Problemtype: internal.Problemtype{
			ProblemtypeData: []internal.ProblemtypeDataItems{
				{
					Description: []internal.LangString{
						{
							Lang:  "eng",
							Value: r.CVEMetadata.CWE,
						},
					},
				},
			},
		},

		Affects: internal.Affects{
			Vendor: internal.Vendor{
				VendorData: []internal.VendorDataItems{
					{
						VendorName: "n/a", // ???
						Product: internal.Product{
							ProductData: []internal.ProductDataItem{
								{
									ProductName: r.Package,
									Version:     versionToVersion(r.Versions),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, additional := range r.AdditionalPackages {
		c.Affects.Vendor.VendorData = append(c.Affects.Vendor.VendorData, internal.VendorDataItems{
			VendorName: "n/a",
			Product: internal.Product{
				ProductData: []internal.ProductDataItem{
					{
						ProductName: additional.Package,
						Version:     versionToVersion(additional.Versions),
					},
				},
			},
		})
	}

	if r.Links.PR != "" {
		c.References.ReferenceData = append(c.References.ReferenceData, internal.Reference{URL: r.Links.PR})
	}
	if r.Links.Commit != "" {
		c.References.ReferenceData = append(c.References.ReferenceData, internal.Reference{URL: r.Links.Commit})
	}
	for _, url := range r.Links.Context {
		c.References.ReferenceData = append(c.References.ReferenceData, internal.Reference{URL: url})
	}

	return c, nil
}

func versionToVersion(versions []report.VersionRange) internal.VersionData {
	vd := internal.VersionData{}
	for _, vr := range versions {
		if vr.Introduced != "" {
			vd.VersionData = append(vd.VersionData, internal.VersionDataItems{
				VersionValue:    vr.Introduced,
				VersionAffected: ">=",
			})
		}
		if vr.Fixed != "" {
			vd.VersionData = append(vd.VersionData, internal.VersionDataItems{
				VersionValue:    vr.Fixed,
				VersionAffected: "<",
			})
		}
	}
	return vd
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprint(os.Stderr, "usage: report2cve report.yaml")
		os.Exit(1)
	}

	reportPath := os.Args[1]
	b, err := ioutil.ReadFile(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %q: %s\n", reportPath, err)
		os.Exit(1)
	}

	var r report.Report
	if err = yaml.UnmarshalStrict(b, &r); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse %q: %s\n", reportPath, err)
		os.Exit(1)
	}

	cve, err := fromReport(&r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate CVE: %s\n", err)
		os.Exit(1)
	}

	// We need to use an encoder so that it doesn't escape angle
	// brackets.
	e := json.NewEncoder(os.Stdout)
	e.SetEscapeHTML(false)
	e.SetIndent("", "\t")
	if err = e.Encode(cve); err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal CVE: %s\n", err)
		os.Exit(1)
	}
}
