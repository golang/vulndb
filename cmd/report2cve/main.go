// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/vulndb/report"
)

// Affects
type Affects struct {
	Vendor Vendor `json:"vendor"`
}

// CVEDataMeta
type CVEDataMeta struct {
	ASSIGNER string `json:"ASSIGNER"`
	ID       string `json:"ID"`
	STATE    string `json:"STATE"`
}

// Description
type Description struct {
	DescriptionData []LangString `json:"description_data"`
}

// LangString
type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Problemtype
type Problemtype struct {
	ProblemtypeData []ProblemtypeDataItems `json:"problemtype_data"`
}

// ProblemtypeDataItems
type ProblemtypeDataItems struct {
	Description []LangString `json:"description"`
}

type VersionData struct {
	VersionData []VersionDataItems `json:"version_data"`
}

type ProductDataItem struct {
	ProductName string      `json:"product_name"`
	Version     VersionData `json:"version"`
}

// Product
type Product struct {
	ProductData []ProductDataItem `json:"product_data"`
}

// Reference
type Reference struct {
	URL string `json:"url"`
}

// References
type References struct {
	ReferenceData []Reference `json:"reference_data"`
}

// Vendor
type Vendor struct {
	VendorData []VendorDataItems `json:"vendor_data"`
}

// VendorDataItems
type VendorDataItems struct {
	Product    Product `json:"product"`
	VendorName string  `json:"vendor_name"`
}

// VersionDataItems
type VersionDataItems struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}

// CVE
type CVE struct {
	DataType    string      `json:"data_type"`
	DataFormat  string      `json:"data_format"`
	DataVersion string      `json:"data_version"`
	CVEDataMeta CVEDataMeta `json:"CVE_data_meta"`

	Affects     Affects     `json:"affects"`
	Description Description `json:"description"`
	Problemtype Problemtype `json:"problemtype"`
	References  References  `json:"references"`
}

func FromReport(report *report.Report) (*CVE, error) {
	if report.CVE != "" {
		return nil, errors.New("report has CVE ID is wrong section (should be in cve_metadata for self-issued CVEs)")
	}
	if report.CVEMetadata == nil {
		return nil, errors.New("report missing cve_metadata section")
	}
	if report.CVEMetadata.ID == "" {
		return nil, errors.New("report missing CVE ID")
	}

	cve := &CVE{
		DataType:    "CVE",
		DataFormat:  "MITRE",
		DataVersion: "4.0",
		CVEDataMeta: CVEDataMeta{
			ID:       report.CVEMetadata.ID,
			ASSIGNER: "security@golang.org",
			STATE:    "PUBLIC",
		},

		Description: Description{
			DescriptionData: []LangString{
				{
					Lang:  "eng",
					Value: strings.TrimSuffix(report.CVEMetadata.Description, "\n"),
				},
			},
		},

		Problemtype: Problemtype{
			ProblemtypeData: []ProblemtypeDataItems{
				{
					Description: []LangString{
						{
							Lang:  "eng",
							Value: report.CVEMetadata.CWE,
						},
					},
				},
			},
		},

		Affects: Affects{
			Vendor: Vendor{
				VendorData: []VendorDataItems{
					{
						VendorName: "n/a", // ???
						Product: Product{
							ProductData: []ProductDataItem{
								{
									ProductName: report.Package,
									Version:     versionToVersion(report.Versions),
								},
							},
						},
					},
				},
			},
		},
	}

	for _, additional := range report.AdditionalPackages {
		cve.Affects.Vendor.VendorData = append(cve.Affects.Vendor.VendorData, VendorDataItems{
			VendorName: "n/a",
			Product: Product{
				ProductData: []ProductDataItem{
					{
						ProductName: additional.Package,
						Version:     versionToVersion(additional.Versions),
					},
				},
			},
		})
	}

	if report.Links.PR != "" {
		cve.References.ReferenceData = append(cve.References.ReferenceData, Reference{URL: report.Links.PR})
	}
	if report.Links.Commit != "" {
		cve.References.ReferenceData = append(cve.References.ReferenceData, Reference{URL: report.Links.Commit})
	}
	for _, url := range report.Links.Context {
		cve.References.ReferenceData = append(cve.References.ReferenceData, Reference{URL: url})
	}

	return cve, nil
}

func versionToVersion(versions []report.VersionRange) VersionData {
	vd := VersionData{}
	for _, vr := range versions {
		if vr.Introduced != "" {
			vd.VersionData = append(vd.VersionData, VersionDataItems{
				VersionValue:    vr.Introduced,
				VersionAffected: ">=",
			})
		}
		if vr.Fixed != "" {
			vd.VersionData = append(vd.VersionData, VersionDataItems{
				VersionValue:    vr.Fixed,
				VersionAffected: "<",
			})
		}
	}
	return vd
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprint(os.Stderr, "usage: report2cve report.toml")
		os.Exit(1)
	}

	reportPath := os.Args[1]
	b, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %q: %s\n", reportPath, err)
		os.Exit(1)
	}

	var r report.Report
	if err = toml.Unmarshal(b, &r); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse %q: %s\n", reportPath, err)
		os.Exit(1)
	}

	cve, err := FromReport(&r)
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
