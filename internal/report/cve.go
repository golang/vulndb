// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"regexp"
	"strings"

	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/stdlib"
)

// cve4 is a wrapper for a CVE in CVE JSON 4.0 (legacy) format.
//
// Note: Fetch is not implemented for CVE4, as it is a legacy format
// which will be phased out soon.
type cve4 struct {
	*cveschema.CVE
}

var _ Source = &cve4{}

func ToCVE4(c *cveschema.CVE) Source {
	return &cve4{CVE: c}
}

func (c *cve4) ToReport(modulePath string) *Report {
	return cveToReport(c.CVE, modulePath)
}

func (c *cve4) SourceID() string {
	return c.ID
}

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

// cveToReport creates a Report struct from a given CVE and modulePath.
func cveToReport(c *cveschema.CVE, modulePath string) *Report {
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
