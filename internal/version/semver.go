// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version provides shared utilities for manipulating
// Go semantic versions with no prefix.
package version

import (
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// IsValid reports whether v is a valid unprefixed semantic version.
func IsValid(v string) bool {
	return semver.IsValid("v" + v)
}

// Before reports whether v < v2, where v and v2 are unprefixed semantic
// versions.
func Before(v, v2 string) bool {
	return semver.Compare("v"+v, "v"+v2) < 0
}

// Canonical returns the canonical, unprefixed form of the version v,
// which should be an unprefixed semantic version.
func Canonical(v string) string {
	return strings.TrimPrefix(semver.Canonical("v"+v), "v")
}

// addSemverPrefix adds a 'v' prefix to s if it isn't already prefixed
// with 'v' or 'go'. This allows us to easily test go-style SEMVER
// strings against normal SEMVER strings.
func addSemverPrefix(s string) string {
	if !strings.HasPrefix(s, "v") && !strings.HasPrefix(s, "go") {
		return "v" + s
	}
	return s
}

// removeSemverPrefix removes the 'v' or 'go' prefixes from go-style
// SEMVER strings, for usage in the public vulnerability format.
func removeSemverPrefix(s string) string {
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "go")
	return s
}

// CanonicalizeSemverPrefix turns a SEMVER string into the canonical
// representation using the 'v' prefix, as used by the OSV format.
// Input may be a bare SEMVER ("1.2.3"), Go prefixed SEMVER ("go1.2.3"),
// or already canonical SEMVER ("v1.2.3").
func CanonicalizeSemverPrefix(s string) string {
	return addSemverPrefix(removeSemverPrefix(s))
}

var (
	// Regexp for matching go tags. The groups are:
	// 1  the major.minor version
	// 2  the patch version, or empty if none
	// 3  the entire prerelease, if present
	// 4  the prerelease type ("beta" or "rc")
	// 5  the prerelease number
	tagRegexp = regexp.MustCompile(`^go(\d+\.\d+)(\.\d+|)((beta|rc|-pre)(\d+))?$`)
)

// This is a modified copy of pkgsite/internal/stdlib:VersionForTag.
func GoTagToSemver(tag string) string {
	if tag == "" {
		return ""
	}

	tag = strings.Fields(tag)[0]
	// Special cases for go1.
	if tag == "go1" {
		return "v1.0.0"
	}
	if tag == "go1.0" {
		return ""
	}
	m := tagRegexp.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	version := "v" + m[1]
	if m[2] != "" {
		version += m[2]
	} else {
		version += ".0"
	}
	if m[3] != "" {
		if !strings.HasPrefix(m[4], "-") {
			version += "-"
		}
		version += m[4] + "." + m[5]
	}
	return version
}
