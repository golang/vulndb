// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"regexp"
	"strings"

	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/stdlib"
)

func vendor(modulePath string) string {
	switch modulePath {
	case stdlib.ModulePath:
		return "Go standard library"
	case stdlib.ToolchainModulePath:
		return "Go toolchain"
	default:
		return modulePath
	}
}

// removeNewlines removes leading and trailing space characters and
// replaces inner newlines with spaces.
func removeNewlines(s string) string {
	newlines := regexp.MustCompile(`\n+`)
	return newlines.ReplaceAllString(strings.TrimSpace(s), " ")
}

// CVEToReport creates a Report struct from a given CVE and modulePath.
func CVEToReport(c *cveschema.CVE, id, modulePath string, pc *proxy.Client) *Report {
	r := cveToReport(c, id, modulePath)
	r.Fix(pc)
	return r
}

func cveToReport(c *cveschema.CVE, id, modulePath string) *Report {
	var description Description
	for _, d := range c.Description.Data {
		description += Description(d.Value + "\n")
	}
	var refs []*Reference
	for _, r := range c.References.Data {
		refs = append(refs, referenceFromUrl(r.URL))
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
	r := &Report{
		ID: id,
		Modules: []*Module{{
			Module: modulePath,
			Packages: []*Package{{
				Package: pkgPath,
			}},
		}},
		Description: description,
		Credits:     credits,
		References:  refs,
	}
	r.addCVE(c.Metadata.ID, getCWE(c), isGoCNA(c))
	return r
}

func getCWE(c *cveschema.CVE) string {
	if len(c.ProblemType.Data) == 0 || len(c.ProblemType.Data[0].Description) == 0 {
		return ""
	}
	return c.ProblemType.Data[0].Description[0].Value
}

func isGoCNA(c *cveschema.CVE) bool {
	return c.Assigner == "security@golang.org"
}

func (r *Report) addCVE(cveID, cwe string, isGoCNA bool) {
	if isGoCNA {
		r.CVEMetadata = &CVEMeta{
			ID:  cveID,
			CWE: cwe,
		}
		return
	}
	r.CVEs = append(r.CVEs, cveID)
}

func CVE5ToReport(c *cveschema5.CVERecord, id, modulePath string, pc *proxy.Client) *Report {
	r := cve5ToReport(c, id, modulePath)
	r.Fix(pc)
	return r
}

func cve5ToReport(c *cveschema5.CVERecord, id, modulePath string) *Report {
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

	// For now, use the first product name as the package path.
	// TODO(tatianabradley): Make this more sophisticated, to consider
	// all the blocks in cna.Affected, versions, etc.
	var pkgPath string
	if affected := cna.Affected; len(affected) > 0 {
		pkgPath = affected[0].Product
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
	modules := []*Module{
		{
			Module:   modulePath,
			Versions: nil,
			Packages: []*Package{
				{
					Package: pkgPath,
				},
			},
		},
	}

	r := &Report{
		ID:          id,
		Modules:     modules,
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
