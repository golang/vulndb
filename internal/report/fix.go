// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"regexp"

	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/version"
)

var commitHashRegex = regexp.MustCompile(`^[a-f0-9]+$`)

func (r *Report) Fix() {
	for _, ref := range r.References {
		ref.URL = fixURL(ref.URL)
	}
	fixVersion := func(mod string, vp *string) {
		v := *vp
		if v == "" {
			return
		}
		if commitHashRegex.MatchString(v) {
			if c, err := proxy.CanonicalModuleVersion(mod, v); err == nil {
				v = c
			}
		}
		v = version.TrimPrefix(v)
		if version.IsValid(v) {
			v = version.Canonical(v)
		}
		*vp = v
	}
	for _, m := range r.Modules {
		for i := range m.Versions {
			fixVersion(m.Module, &m.Versions[i].Introduced)
			fixVersion(m.Module, &m.Versions[i].Fixed)
		}
		fixVersion(m.Module, &m.VulnerableAt)
	}
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
