// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TODO: Add tests for helper functions that call the proxy.

var (
	validStdLibLinks = Links{
		PR:     "https://go.dev/cl/12345",
		Commit: "https://go.googlesource.com/go/+/abcde",
		Context: []string{
			"https://groups.google.com/g/golang-announce/c/12345",
			"https://go.dev/issue/12345",
		},
	}
)

func TestLint(t *testing.T) {
	jan2000 := time.Date(2000, time.January, 0, 0, 0, 0, 0, time.UTC)
	jan2022 := time.Date(2022, time.January, 0, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		desc   string
		dir    string // default: "reports/"
		report Report
		want   []string
	}{
		{
			desc: "no modules",
			report: Report{
				Description: "description",
			},
			want: []string{"no modules"},
		},
		{
			desc: "missing module",
			report: Report{
				Modules: []*Module{{
					// mo module
					Packages: []*Package{{
						Package: "golang.org/x/vulndb",
					}},
				}},
				Description: "description",
			},
			want: []string{"missing module"},
		},
		{
			desc: "missing description",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				// no description
				Links: validStdLibLinks,
			},
			want: []string{"missing description"},
		},
		{
			desc: "missing package path",
			report: Report{
				Modules: []*Module{{
					Module: "golang.org/x/vulndb",
					Packages: []*Package{{
						Symbols: []string{"Foo"},
					}},
				}},
				Description: "description",
			},
			want: []string{"missing package"},
		},
		{
			desc: "third party: module is not a prefix of package",
			report: Report{
				Modules: []*Module{{
					Module: "golang.org/x/vulndb",
					Packages: []*Package{{
						Package: "golang.org/x/crypto",
					}},
				}},
				Description: "description",
			},
			want: []string{"module must be a prefix of package"},
		},
		{
			desc: "third party: invalid import path",
			report: Report{
				Modules: []*Module{{
					Module: "invalid.",
					Packages: []*Package{{
						Package: "invalid.",
					}},
					Versions: []VersionRange{{
						Fixed: "1.2.1",
					}},
				}},
				Description: "description",
			},
			want: []string{"malformed import path",
				"unable to retrieve module versions from proxy"},
		},
		{
			desc: "standard library: missing package",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						// no package
						Symbols: []string{"Atoi"},
					}},
				}},
				Description: "description",
				Links:       validStdLibLinks,
			},
			want: []string{"missing package"},
		},
		{
			desc: "overlapping version ranges",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Versions: []VersionRange{{
						Fixed: "1.2.1",
					}, {
						Fixed: "1.3.2",
					}},
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				Links:       validStdLibLinks,
			},
			want: []string{"version ranges overlap"},
		},
		{
			desc: "fixed before introduced",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Versions: []VersionRange{{
						Introduced: "1.3",
						Fixed:      "1.2.1",
					}},
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				Links:       validStdLibLinks,
			},
			want: []string{`version "1.3" >= "1.2.1"`},
		},
		{
			desc: "invalid semantic version",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Versions: []VersionRange{{
						Introduced: "1.3.X",
					}},
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				Links:       validStdLibLinks,
			},
			want: []string{`invalid semantic version: "1.3.X"`},
		},
		{
			desc: "last modified before published",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description:  "description",
				LastModified: &jan2000,
				Published:    jan2022,
				Links:        validStdLibLinks,
			},
			want: []string{"last_modified is before published"},
		},
		{
			desc: "bad cve identifier",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEs:        []string{"CVE.12345.456"},
				Links:       validStdLibLinks,
			},
			want: []string{"malformed cve identifier"},
		},
		{
			desc: "cve and cve metadata both present",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEs:        []string{"CVE-2022-1234545"},
				CVEMetadata: &CVEMeta{
					ID: "CVE-2022-23456",
				},
				Links: validStdLibLinks,
			},
			want: []string{"only one of cve and cve_metadata.id should be present"},
		},
		{
			desc: "missing cve metadata id",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEMetadata: &CVEMeta{
					// no id
				},
				Links: validStdLibLinks,
			},
			want: []string{"cve_metadata.id is required"},
		},
		{
			desc: "bad cve metadata id",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEMetadata: &CVEMeta{
					ID: "CVE.2022.00000",
				},
				Links: validStdLibLinks,
			},
			want: []string{"malformed cve_metadata.id identifier"},
		},
		{
			desc: "unfixed links",
			report: Report{
				Modules: []*Module{{
					Module: "golang.org/x/vulndb",
					Packages: []*Package{{
						Package: "golang.org/x/vulndb",
					}},
				}},
				Description: "description",
				Links: Links{
					Commit: "https://github.com/golang/go/commit/12345",
					Context: []string{
						"https://github.com/golang/go/issues/12345",
						"https://golang.org/xxx",
						"https://groups.google.com/forum/#!/golang-announce/12345/1/"},
				},
			},
			want: []string{
				`"https://github.com/golang/go/issues/12345" should be "https://go.dev/issue/12345"`,
				`"https://golang.org/xxx" should be "https://go.dev/xxx"`,
				`"https://github.com/golang/go/commit/12345" should be "https://go.googlesource.com/+/12345"`,
				`"https://groups.google.com/forum/#!/golang-announce/12345/1/" should be "https://groups.google.com/g/golang-announce/c/12345/m/1/"`},
		},
		{
			desc: "standard library: unfixed/missing links",
			report: Report{
				Modules: []*Module{{
					Module: "std",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				Links: Links{
					PR:     "https://go-review.googlesource.com/c/go/+/12345",
					Commit: "https://github.com/golang/go/commit/12345",
					Context: []string{
						"https://github.com/golang/go/issues/12345",
						// no announce link
					},
				},
			},
			want: []string{
				// Standard library specific errors.
				"links.pr should contain a PR link",
				"links.commit commit link should match",
				"links.context should contain an issue link",
				"links.context should contain an announcement link",
				"links.context should contain only PR, commit, issue and announcement links",
				// Unfixed link errors.
				`"https://github.com/golang/go/commit/12345" should be "https://go.googlesource.com/+/12345"`,
				`"https://github.com/golang/go/issues/12345" should be "https://go.dev/issue/12345"`,
			},
		},
		{
			desc: "invalid URL",
			report: Report{
				Modules: []*Module{{
					Module: "golang.org/x/vulndb",
					Packages: []*Package{{
						Package: "golang.org/x/vulndb",
					}},
				}},
				Description: "description",
				Links: Links{
					PR: "go.dev/cl/12345", // needs "https://" prefix
				},
			},
			want: []string{
				`"go.dev/cl/12345" is not a valid URL`,
			},
		},
		{
			desc: "excluded in wrong dir",
			report: Report{
				Excluded: "NOT_GO_CODE",
				CVEs:     []string{"CVE-2022-1234545"},
			},
			want: []string{
				`report in reports/ must not have excluded set`,
				`no modules`,
				`missing description`,
			},
		},
		{
			desc:   "report in wrong dir",
			dir:    "excluded",
			report: Report{},
			want: []string{
				`report in excluded/ must have excluded set`,
				`excluded report must have at least one associated CVE or GHSA`,
			},
		},
		{
			desc: "excluded",
			dir:  "excluded",
			report: Report{
				Excluded: "NOT_GO_CODE",
				CVEs:     []string{"CVE-2022-1234545"},
			},
		},
	} {
		dir := test.dir
		if dir == "" {
			dir = "reports"
		}
		got := test.report.Lint(dir + "/GO-0000-000.yaml")

		var missing []string
		for _, w := range test.want {
			found := false
			for _, g := range got {
				if strings.Contains(g, w) {
					found = true
					continue
				}
			}
			if !found {
				missing = append(missing, w)
			}
		}
		if len(missing) > 0 {
			var buf bytes.Buffer
			if err := test.report.encode(&buf); err != nil {
				t.Error(err)
			}
			t.Errorf("TestLint(%q): missing expected lint errors in report:\n"+
				"%v\n"+
				"got:  %q\n"+
				"want: %q\n", test.desc, buf.String(), got, missing)
		}

		// Check for unexpected lint errors if there are no missing ones.
		if len(missing) == 0 {
			var unexpected []string
			for _, g := range got {
				found := false
				for _, w := range test.want {
					if strings.Contains(g, w) {
						found = true
						continue
					}
				}
				if !found {
					unexpected = append(unexpected, g)
				}
			}
			if len(unexpected) > 0 {
				var buf bytes.Buffer
				if err := test.report.encode(&buf); err != nil {
					t.Error(err)
				}
				t.Errorf("TestLint(%q): unexpected lint errors in report:\n"+
					"%v\n"+
					"got:  %q\n", test.desc, buf.String(), unexpected)
			}
		}
	}
}
