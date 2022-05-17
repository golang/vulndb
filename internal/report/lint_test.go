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

func TestLint(t *testing.T) {
	jan2000 := time.Date(2000, time.January, 0, 0, 0, 0, 0, time.UTC)
	jan2022 := time.Date(2022, time.January, 0, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		desc   string
		report Report
		want   []string
	}{
		{
			desc: "no packages",
			report: Report{
				Description: "description",
			},
			want: []string{"no packages"},
		},
		{
			desc: "missing module",
			report: Report{
				Packages: []Package{{
					// no module
					Package: "test.com/a/package",
				}},
				Description: "description",
			},
			want: []string{"missing module"},
		},
		{
			desc: "missing description",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
				}},
				// no description
			},
			want: []string{"missing description"},
		},
		{
			desc: "third party: redundant module and package",
			report: Report{
				Packages: []Package{{
					Module:  "github.com/golang/vulndb",
					Package: "github.com/golang/vulndb",
				}},
				Description: "description",
			},
			want: []string{"package is redundant and can be removed"},
		},
		{
			desc: "third party: module is not a prefix of package",
			report: Report{
				Packages: []Package{{
					Module:  "github.com/golang/vulndb",
					Package: "github.com/golang/crypto",
				}},
				Description: "description",
			},
			want: []string{"module must be a prefix of package"},
		},
		{
			desc: "third party: invalid import path",
			report: Report{
				Packages: []Package{{
					Module: "invalid.",
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
				Packages: []Package{{
					Module: "std",
					// no package
				}},
				Description: "description",
			},
			want: []string{"missing package"},
		},
		{
			desc: "overlapping version ranges",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
					Versions: []VersionRange{{
						Fixed: "1.2.1",
					}, {
						Fixed: "1.3.2",
					}},
				}},
				Description: "description",
			},
			want: []string{"version ranges overlap"},
		},
		{
			desc: "fixed before introduced",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
					Versions: []VersionRange{{
						Introduced: "1.3",
						Fixed:      "1.2.1",
					}},
				}},
				Description: "description",
			},
			want: []string{`version "1.3" >= "1.2.1"`},
		},
		{
			desc: "invalid semantic version",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
					Versions: []VersionRange{{
						Introduced: "1.3.X",
					}},
				}},
				Description: "description",
			},
			want: []string{`invalid semantic version: "1.3.X"`},
		},
		{
			desc: "last modified before published",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
				}},
				Description:  "description",
				LastModified: &jan2000,
				Published:    jan2022,
			},
			want: []string{"last_modified is before published"},
		},
		{
			desc: "bad cve identifier",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
				}},
				Description: "description",
				CVEs:        []string{"CVE.123.456"},
			},
			want: []string{"malformed cve identifier"},
		},
		{
			desc: "cve and cve metadata both present",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
				}},
				Description: "description",
				CVEs:        []string{"CVE-2022-12345"},
				CVEMetadata: &CVEMeta{
					ID: "CVE-2022-23456",
				},
			},
			want: []string{"only one of cve and cve_metadata.id should be present"},
		},
		{
			desc: "missing cve metadata id",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
				}},
				Description: "description",
				CVEMetadata: &CVEMeta{
					// no id
				},
			},
			want: []string{"cve_metadata.id is required"},
		},
		{
			desc: "bad cve metadata id",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
				}},
				Description: "description",
				CVEMetadata: &CVEMeta{
					ID: "CVE.2022.00000",
				},
			},
			want: []string{"malformed cve_metadata.id identifier"},
		},
		{
			desc: "unfixed links",
			report: Report{
				Packages: []Package{{
					Module:  "std",
					Package: "time",
				}},
				Description: "description",
				Links: Links{
					Commit: "https://github.com/golang/go/commit/123",
					Context: []string{
						"https://github.com/golang/go/issues/123",
						"https://golang.org/xxx",
						"https://groups.google.com/forum/#!/golang-announce/123/1/"},
				},
			},
			want: []string{
				`"https://github.com/golang/go/issues/123" should be "https://go.dev/issue/123"`,
				`"https://golang.org/xxx" should be "https://go.dev/xxx"`,
				`"https://github.com/golang/go/commit/123" should be "https://go.googlesource.com/+/123"`,
				`"https://groups.google.com/forum/#!/golang-announce/123/1/" should be "https://groups.google.com/g/golang-announce/c/123/m/1/"`},
		},
	} {
		got := test.report.Lint()

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

func TestLintFile(t *testing.T) {
	f := "testdata/report.yaml"
	lintErrs, err := LintFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(lintErrs) > 0 {
		t.Errorf("unexpected lint errors for %q:\n"+
			"got:  %q\n"+
			"want: []", f, lintErrs)
	}
}
