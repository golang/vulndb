// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package idstr

import (
	"regexp"
	"strings"
)

var (
	nistPrefix       = "https://nvd.nist.gov/vuln/detail/"
	mitrePrefixMatch = "https://.*cve.*org/.*"

	ghsaGlobalPrefix    = "https://github.com/advisories/"
	ghsaRepoPrefixMatch = "https://github.com/.+/advisories/"

	godevPrefix = "https://pkg.go.dev/vuln/"

	cveLink  = strictRE(oneOf(mitrePrefixMatch, nistPrefix), cveStr)
	ghsaLink = strictRE(oneOf(ghsaGlobalPrefix, ghsaRepoPrefixMatch), ghsaStr)

	ghsaGlobalLink = strictRE(ghsaGlobalPrefix, ghsaStr)
	ghsaRepoLink   = strictRE(ghsaRepoPrefixMatch, ghsaStr)
	goAdvisoryLink = strictRE(godevPrefix, goIDStr)
)

var (
	advisoryPrefixes = []string{nistPrefix, mitrePrefixMatch, ghsaGlobalPrefix, ghsaRepoPrefixMatch, godevPrefix}
	advisoryREs      = []*regexp.Regexp{cveLink, ghsaLink, goAdvisoryLink}
)

func IsGoAdvisory(u string) bool {
	return goAdvisoryLink.MatchString(u)
}

func GoAdvisory(id string) string {
	return godevPrefix + id
}

func IsAdvisory(u string) bool {
	for _, re := range advisoryREs {
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

func IsAdvisoryForOneOf(u string, aliases []string) (string, bool) {
	for _, prefix := range advisoryPrefixes {
		re := strictRE(prefix, aliases...)
		if m := re.FindStringSubmatch(u); len(m) == 2 {
			return m[1], true
		}
	}
	return "", false
}

func AdvisoryLink(id string) string {
	switch {
	case IsCVE(id):
		return nistPrefix + id
	case IsGHSA(id):
		return ghsaGlobalPrefix + id
	case IsGoID(id):
		return GoAdvisory(id)
	default:
		return ""
	}
}

func IsCVELink(u string) bool {
	return cveLink.MatchString(u)
}

func IsGHSAGlobalLink(u string) bool {
	return ghsaGlobalLink.MatchString(u)
}

func IsGHSARepoLink(u string) bool {
	return ghsaRepoLink.MatchString(u)
}

func oneOf(strs ...string) string {
	return strings.Join(strs, `|`)
}

func strictRE(prefix string, ids ...string) *regexp.Regexp {
	return regexp.MustCompile(`^` + prefix + `(` + oneOf(ids...) + `)$`)
}
