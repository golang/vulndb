// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package idstr

import "regexp"

var (
	NISTLink       = regexp.MustCompile(`^https://nvd.nist.gov/vuln/detail/(` + cveStr + `)$`)
	GHSALink       = regexp.MustCompile(`^https://github.com/.*/(` + ghsaStr + `)$`)
	MITRELink      = regexp.MustCompile(`^https://cve.mitre.org/.*(` + cveStr + `)$`)
	goAdvisoryLink = regexp.MustCompile(`^https://pkg.go.dev/vuln/(` + goIDStr + `)$`)
)

func IsGoAdvisory(u string) bool {
	return goAdvisoryLink.MatchString(u)
}
