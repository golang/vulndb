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

func getVendor(modulePath string) string {
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
func CVEToReport(c *cveschema.CVE, modulePath string) *Report {
	var description string
	for _, d := range c.Description.Data {
		description += d.Value + "\n"
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
	// New standard library and x/ repo CVEs are likely maintained by
	// the Go CNA.
	if stdlib.IsStdModule(modulePath) || stdlib.IsCmdModule(modulePath) ||
		stdlib.IsXModule(modulePath) {
		r.CVEMetadata = &CVEMeta{
			ID:  c.Metadata.ID,
			CWE: "TODO",
		}
	} else {
		r.CVEs = []string{c.Metadata.ID}
	}
	r.Fix()
	return r
}
