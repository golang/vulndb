// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package version provides shared utilities for manipulating
// Go semantic versions with no prefix.
package version

import (
	"fmt"
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

// Major returns the major version (e.g. "v2") of the
// unprefixed semantic version v.
func Major(v string) string {
	return semver.Major("v" + v)
}

// Canonical returns the canonical, unprefixed form of the version v,
// which should be an unprefixed semantic version.
// Unlike semver.Canonical, this function preserves build tags.
func Canonical(v string) string {
	sv := "v" + v
	build := semver.Build(sv)
	c := strings.TrimPrefix(semver.Canonical(sv), "v")
	return c + build
}

// TrimPrefix removes the 'v' or 'go' prefix from the given
// semantic version v.
func TrimPrefix(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "go")
	return v
}

var commitHashRegex = regexp.MustCompile(`^[a-f0-9]+$`)

func IsCommitHash(v string) bool {
	return commitHashRegex.MatchString(v)
}

// SemverToGoTag returns the Go standard library repository tag
// for the given unprefixed semver version.
// Go tags differ from standard semantic versions in a few ways,
// such as beginning with "go" instead of "v".
func SemverToGoTag(v string) (string, error) {
	// Add the "v" prefix back in, as the copied function relies
	// on it.
	// TODO(tatianabradley): Edit function body to not expect "v" prefix.
	if !strings.HasPrefix("v", v) {
		v = "v" + v
	}
	// Rest of function copied from
	// https://github.com/golang/vuln/blob/03fad6f89d5c526e6a0d4e4176efa648c38919c2/internal/scan/stdlib.go
	if strings.HasPrefix(v, "v0.0.0") {
		return "master", nil
	}
	// Special case: 1.0.0 => go1.
	if v == "v1.0.0" {
		return "go1", nil
	}
	if !semver.IsValid(v) {
		return "", fmt.Errorf("%s: invalid semver", v)
	}
	goVersion := semver.Canonical(v)
	prerelease := semver.Prerelease(goVersion)
	versionWithoutPrerelease := strings.TrimSuffix(goVersion, prerelease)
	patch := strings.TrimPrefix(versionWithoutPrerelease, semver.MajorMinor(goVersion)+".")
	if patch == "0" {
		versionWithoutPrerelease = strings.TrimSuffix(versionWithoutPrerelease, ".0")
	}
	goVersion = fmt.Sprintf("go%s", versionWithoutPrerelease)
	if prerelease != "" {
		// Go prereleases look like  "beta1" instead of "beta.1".
		// "beta1" is bad for sorting (since beta10 comes before beta9), so
		// require the dot form.
		i := finalDigitsIndex(prerelease)
		if i >= 1 {
			if prerelease[i-1] != '.' {
				return "", fmt.Errorf("%s: final digits in a prerelease must follow a period", v)
			}
			// Remove the dot.
			prerelease = prerelease[:i-1] + prerelease[i:]
		}
		goVersion += strings.TrimPrefix(prerelease, "-")
	}
	return goVersion, nil
}

// finalDigitsIndex returns the index of the first digit in the sequence of digits ending s.
// If s doesn't end in digits, it returns -1.
func finalDigitsIndex(s string) int {
	// Assume ASCII (since the semver package does anyway).
	var i int
	for i = len(s) - 1; i >= 0; i-- {
		if s[i] < '0' || s[i] > '9' {
			break
		}
	}
	if i == len(s)-1 {
		return -1
	}
	return i + 1
}
