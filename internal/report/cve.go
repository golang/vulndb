// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/version"
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
		Source: &Source{
			ID: c.Metadata.ID,
		},
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

	r := &Report{
		ID:          id,
		Modules:     affectedToModules(cna.Affected, modulePath),
		Summary:     Summary(cna.Title),
		Description: description,
		Credits:     credits,
		References:  refs,
		Source: &Source{
			ID: c.Metadata.ID,
		},
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
