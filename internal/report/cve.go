// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"sort"
	"strings"

	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/stdlib"
)

// ToCVE creates a CVE from a reports/GO-YYYY-NNNN.yaml file.
func ToCVE(reportPath string) (_ *cveschema.CVE, err error) {
	defer derrors.Wrap(&err, "report.ToCVE(%q)", reportPath)

	r, err := Read(reportPath)
	if err != nil {
		return nil, err
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

	c := &cveschema.CVE{
		DataType:    "CVE",
		DataFormat:  "MITRE",
		DataVersion: "4.0",
		Metadata: cveschema.Metadata{
			ID:       r.CVEMetadata.ID,
			Assigner: "security@golang.org",
			State:    cveschema.StatePublic,
		},

		Description: cveschema.Description{
			Data: []cveschema.LangString{
				{
					Lang:  "eng",
					Value: strings.TrimSuffix(r.CVEMetadata.Description, "\n"),
				},
			},
		},

		ProblemType: cveschema.ProblemType{
			Data: []cveschema.ProblemTypeDataItem{
				{
					Description: []cveschema.LangString{
						{
							Lang:  "eng",
							Value: r.CVEMetadata.CWE,
						},
					},
				},
			},
		},
	}

	for _, p := range r.Packages {
		c.Affects.Vendor.Data = append(c.Affects.Vendor.Data, cveschema.VendorDataItem{
			VendorName: "n/a", // ???
			Product: cveschema.Product{
				Data: []cveschema.ProductDataItem{
					{
						ProductName: p.Package,
						Version:     versionToVersion(p.Versions),
					},
				},
			},
		})
	}

	if r.Links.PR != "" {
		c.References.Data = append(c.References.Data, cveschema.Reference{URL: r.Links.PR})
	}
	if r.Links.Commit != "" {
		c.References.Data = append(c.References.Data, cveschema.Reference{URL: r.Links.Commit})
	}
	for _, url := range r.Links.Context {
		c.References.Data = append(c.References.Data, cveschema.Reference{URL: url})
	}

	return c, nil
}

func versionToVersion(versions []VersionRange) cveschema.VersionData {
	vd := cveschema.VersionData{}
	for _, vr := range versions {
		if vr.Introduced != "" {
			vd.Data = append(vd.Data, cveschema.VersionDataItem{
				VersionValue:    vr.Introduced,
				VersionAffected: ">=",
			})
		}
		if vr.Fixed != "" {
			vd.Data = append(vd.Data, cveschema.VersionDataItem{
				VersionValue:    vr.Fixed,
				VersionAffected: "<",
			})
		}
	}
	return vd
}

// CVEToReport creates a Report struct from a given CVE and modulePath.
func CVEToReport(c *cveschema.CVE, modulePath string) *Report {
	var description string
	for _, d := range c.Description.Data {
		description += d.Value + "\n"
	}
	var (
		pr, commit string
		context    []string
	)
	for _, r := range c.References.Data {
		if strings.Contains(r.URL, "go-review.googlesource.com") {
			pr = r.URL
		} else if strings.Contains(r.URL, "commit") {
			commit = r.URL
		} else if strings.Contains(r.URL, "pull") {
			pr = r.URL
		} else {
			context = append(context, r.URL)
		}
	}
	sort.Strings(context)
	var credits []string
	for _, v := range c.Credit.Data.Description.Data {
		credits = append(credits, v.Value)
	}
	credit := strings.Join(credits, "\t")

	var pkgPath string
	if data := c.Affects.Vendor.Data; len(data) > 0 {
		if data2 := data[0].Product.Data; len(data2) > 0 {
			pkgPath = data2[0].ProductName
		}
	}
	r := &Report{
		Packages: []Package{{
			Module:  modulePath,
			Package: pkgPath,
		}},
		Description: description,
		CVEs:        []string{c.Metadata.ID},
		Credit:      credit,
		Links: Links{
			Commit:  commit,
			PR:      pr,
			Context: context,
		},
	}
	if !strings.Contains(modulePath, ".") {
		r.Packages[0].Module = stdlib.ModulePath
		r.Packages[0].Package = modulePath
	}
	if stdlib.Contains(r.Packages[0].Module) && r.Packages[0].Package == "" {
		r.Packages[0].Package = modulePath
	}
	r.Fix()
	return r
}
