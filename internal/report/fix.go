// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/version"
)

var commitHashRegex = regexp.MustCompile(`^[a-f0-9]+$`)

func (r *Report) Fix() {
	for _, ref := range r.References {
		ref.URL = fixURL(ref.URL)
	}
	for _, m := range r.Modules {
		m.fixVersions()
	}
	fixLines := func(sp *string) {
		*sp = fixLineLength(*sp, maxLineLength)
	}
	fixLines(&r.Summary)
	fixLines(&r.Description)
	if r.CVEMetadata != nil {
		fixLines(&r.CVEMetadata.Description)
	}
}

// fixVersions replaces each version with its canonical form (if possible),
// sorts version ranges, and collects version ranges into a compact form.
func (m *Module) fixVersions() {
	fixVersion := func(v string) string {
		if v == "" {
			return ""
		}
		if commitHashRegex.MatchString(v) {
			if c, err := proxy.CanonicalModuleVersion(m.Module, v); err == nil {
				v = c
			}
		}
		v = version.TrimPrefix(v)
		if version.IsValid(v) {
			v = version.Canonical(v)
		}
		return v
	}

	for i, vr := range m.Versions {
		m.Versions[i].Introduced = fixVersion(vr.Introduced)
		m.Versions[i].Fixed = fixVersion(vr.Fixed)
	}
	m.VulnerableAt = fixVersion(m.VulnerableAt)

	sort.SliceStable(m.Versions, func(i, j int) bool {
		intro, fixed := m.Versions[i].Introduced, m.Versions[i].Fixed
		intro2, fixed2 := m.Versions[j].Introduced, m.Versions[j].Fixed
		switch {
		case intro != "" && intro2 != "":
			return version.Before(intro, intro2)
		case intro != "" && fixed2 != "":
			return version.Before(intro, fixed2)
		case fixed != "" && intro2 != "":
			return version.Before(fixed, intro2)
		case fixed != "" && fixed2 != "":
			return version.Before(fixed, fixed2)
		default:
			return false
		}
	})

	// Collect together version ranges that don't need to be separate,
	// e.g:
	// [ {Introduced: 1.1.0}, {Fixed: 1.2.0} ] becomes
	// [ {Introduced: 1.1.0, Fixed: 1.2.0} ].
	for i := 0; i < len(m.Versions); i++ {
		if i != 0 {
			current, prev := m.Versions[i], m.Versions[i-1]
			if (prev.Introduced != "" && prev.Fixed == "") &&
				(current.Introduced == "" && current.Fixed != "") {
				m.Versions[i-1].Fixed = current.Fixed
				m.Versions = append(m.Versions[:i], m.Versions[i+1:]...)
				i--
			}
		}
	}

	if m.VulnerableAt == "" {
		v, err := m.guessVulnerableAt(proxy.DefaultClient)
		// For now, ignore errors and leave the field blank if it can't
		// be determined.
		if err == nil {
			m.VulnerableAt = v
		}
	}
}

type proxyClient interface {
	Latest(path string) (string, error)
	Versions(path string) ([]string, error)
}

// guessVulnerableAt attempts to find a vulnerable_at
// version using the module proxy.
// If there is no fix, the latest version is used.
func (m *Module) guessVulnerableAt(pc proxyClient) (string, error) {
	if m.IsFirstParty() {
		return "", errors.New("cannot auto-guess vulnerable_at for first-party modules")
	}

	// Find the last fixed version, assuming the version ranges are sorted.
	fixed := ""
	if len(m.Versions) > 0 {
		fixed = m.Versions[len(m.Versions)-1].Fixed
	}

	// If there is no fix, find the latest version of the module.
	if fixed == "" {
		latest, err := pc.Latest(m.Module)
		if err != nil || latest == "" {
			return "", fmt.Errorf("could not find latest version from proxy: %s", err)
		}

		return latest, nil
	}

	// If the latest fixed version is a 0.0.0 pseudo-version, or not a valid version,
	// don't attempt to determine the vulnerable_at version.
	if !version.IsValid(fixed) {
		return "", errors.New("cannot auto-guess when fixed version is invalid")
	}
	if strings.HasPrefix(fixed, "0.0.0-") {
		return "", errors.New("cannot auto-guess when fixed version is 0.0.0 pseudo-version")
	}

	// Otherwise, find the version right before the fixed version.
	vs, err := pc.Versions(m.Module)
	if err != nil {
		return "", fmt.Errorf("could not find versions from proxy: %s", err)
	}
	for i := len(vs) - 1; i >= 0; i-- {
		if version.Before(vs[i], fixed) {
			return vs[i], nil
		}
	}

	return "", fmt.Errorf("could not find tagged version less than fixed (lowest version is %s)", vs[0])
}

// fixLineLength returns a copy of s with all lines trimmed to <=n characters
// (with the exception of single-word lines).
// It preserves paragraph breaks (indicated by "\n\n") and markdown-style list
// breaks.
func fixLineLength(s string, n int) string {
	var result strings.Builder
	result.Grow(len(s))
	for i, paragraph := range strings.Split(toParagraphs(s), "\n\n") {
		if i > 0 {
			result.WriteString("\n\n")
		}
		var lines []string
		for _, forcedLine := range strings.Split(paragraph, "\n") {
			words := strings.Split(forcedLine, " ")
			start, length := 0, 0
			for k, word := range words {
				newLength := length + len(word)
				if length > 0 {
					newLength++ // space character
				}
				if newLength <= n {
					length = newLength
					continue
				}
				// Adding the word would put the line over the max length,
				// so add the line as is (if it is non-empty).
				if length > 0 {
					lines = append(lines, strings.Join(words[start:k], " "))
				}
				// Begin a new line with just the word.
				start, length = k, len(word)
			}
			// Add the last line.
			if length > 0 {
				lines = append(lines, strings.Join(words[start:], " "))
			}
		}
		result.WriteString(strings.Join(lines, "\n"))
	}
	return result.String()
}

var urlReplacements = []struct {
	re   *regexp.Regexp
	repl string
}{{
	regexp.MustCompile(`golang.org`),
	`go.dev`,
}, {
	regexp.MustCompile(`https?://groups.google.com/forum/\#\![^/]*/([^/]+)/([^/]+)/(.*)`),

	`https://groups.google.com/g/$1/c/$2/m/$3`,
}, {
	regexp.MustCompile(`.*github.com/golang/go/issues`),
	`https://go.dev/issue`,
}, {
	regexp.MustCompile(`.*github.com/golang/go/commit`),
	`https://go.googlesource.com/+`,
},
}

func fixURL(u string) string {
	for _, repl := range urlReplacements {
		u = repl.re.ReplaceAllString(u, repl.repl)
	}
	return u
}
