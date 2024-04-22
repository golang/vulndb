// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package idstr provides utilities for working with vulnerability
// identifier strings.
package idstr

import "regexp"

const ghsaStr = `GHSA-[^-]{4}-[^-]{4}-[^-]{4}`

var (
	ghsaRE, ghsaStrict = re(ghsaStr)
)

func IsGHSA(s string) bool {
	return ghsaStrict.MatchString(s)
}

func FindGHSA(s string) string {
	return ghsaRE.FindString(s)
}

const cveStr = `CVE-\d{4}-\d{4,}`

var (
	cveRE, cveStrict = re(cveStr)
)

func IsCVE(s string) bool {
	return cveStrict.MatchString(s)
}

func FindCVE(s string) string {
	return cveRE.FindString(s)
}

const goIDStr = `GO-\d{4}-\d{4,}`

var (
	_, goIDStrict = re(goIDStr)
)

func IsGoID(s string) bool {
	return goIDStrict.MatchString(s)
}

func re(s string) (*regexp.Regexp, *regexp.Regexp) {
	return regexp.MustCompile(s), regexp.MustCompile(`^` + s + `$`)
}

// IsIdentifier returns whether the given ID is a recognized identifier
// (currently, either a GHSA, CVE, or Go ID).
func IsIdentifier(id string) bool {
	return IsAliasType(id) || IsGoID(id)
}

// IsAliasType returns whether the given ID is a recognized alias type
// (currently, either a GHSA or CVE).
func IsAliasType(id string) bool {
	return IsGHSA(id) || IsCVE(id)
}
