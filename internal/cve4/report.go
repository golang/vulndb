// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve4

import (
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/stdlib"
)

var _ report.Source = &CVE{}

func (c *CVE) ToReport(modulePath string) *report.Report {
	return cveToReport(c, modulePath)
}

func (c *CVE) SourceID() string {
	return c.ID
}

func (c *CVE) ReferenceURLs() []string {
	var result []string
	for _, r := range c.References.Data {
		result = append(result, r.URL)
	}
	return result
}

// cveToReport creates a Report struct from a given CVE and modulePath.
func cveToReport(c *CVE, modulePath string) *report.Report {
	var description report.Description
	for _, d := range c.Description.Data {
		description += report.Description(d.Value + "\n")
	}
	var refs []*report.Reference
	for _, r := range c.References.Data {
		refs = append(refs, report.ReferenceFromUrl(r.URL))
	}
	var credits []string
	for _, v := range c.Credit.Data.Description.Data {
		credits = append(credits, v.Value)
	}

	var pkgPath string
	if data := c.Affects.Vendor.Data; len(data) > 0 {
		if data2 := data[0].Product.Data; len(data2) > 0 {
			pkgPath = data2[0].ProductName
		}
	}
	if stdlib.Contains(modulePath) {
		pkgPath = modulePath
		modulePath = stdlib.ModulePath
	}
	if modulePath == "" {
		modulePath = "TODO"
	}
	if pkgPath == "" {
		pkgPath = modulePath
	}
	r := &report.Report{
		Modules: []*report.Module{{
			Module: modulePath,
			Packages: []*report.Package{{
				Package: pkgPath,
			}},
		}},
		Description: description,
		Credits:     credits,
		References:  refs,
	}
	r.AddCVE(c.Metadata.ID, getCWE(c), isGoCNA(c))
	return r
}

func getCWE(c *CVE) string {
	if len(c.ProblemType.Data) == 0 || len(c.ProblemType.Data[0].Description) == 0 {
		return ""
	}
	return c.ProblemType.Data[0].Description[0].Value
}

func isGoCNA(c *CVE) bool {
	return c.Assigner == "security@golang.org"
}
