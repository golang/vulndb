// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"golang.org/x/vulndb/internal/osv"
)

var proxy = flag.Bool("proxy", false, "test helper functions that call the proxy")

// TODO: Add tests for helper functions that call the proxy.

var (
	validStdLibReferences = []*Reference{
		{Type: osv.ReferenceTypeFix, URL: "https://go.dev/cl/12345"},
		{Type: osv.ReferenceTypeWeb, URL: "https://groups.google.com/g/golang-announce/c/12345"},
		{Type: osv.ReferenceTypeReport, URL: "https://go.dev/issue/12345"},
	}
)

func validXReport(f func(r *Report)) Report {
	r := Report{
		Modules: []*Module{{
			Module:       "golang.org/x/net",
			VulnerableAt: "1.2.3",
			Packages: []*Package{{
				Package: "golang.org/x/net/http2",
			}},
		}},
		Description: "description",
	}
	f(&r)
	return r
}

func TestLint(t *testing.T) {
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
					// no module field
					VulnerableAt: "1.2.3",
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
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				// no description
				References: validStdLibReferences,
			},
			want: []string{"missing description"},
		},
		{
			desc: "missing package path",
			report: Report{
				Modules: []*Module{{
					Module:       "golang.org/x/vulndb",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Symbols: []string{"Foo"},
					}},
				}},
				Description: "description",
			},
			want: []string{"missing package"},
		},
		{
			desc: "missing vulnerable at and skip fix",
			report: Report{
				Modules: []*Module{{
					Module: "golang.org/x/vulndb",
					// no vulnerable at
					Packages: []*Package{{
						Package: "golang.org/x/vulndb/internal/lint",
						Symbols: []string{"Foo"},
					}},
				}},
				Description: "description",
			},
			want: []string{"missing skip_fix and vulnerable_at"},
		},
		{
			desc: "skip fix given",
			report: Report{
				Modules: []*Module{{
					Module: "golang.org/x/vulndb",
					// no vulnerable at
					Packages: []*Package{{
						Package: "golang.org/x/vulndb/internal/lint",
						Symbols: []string{"Foo"},
						SkipFix: "reason given",
					}},
				}},
				Description: "description",
			},
			want: []string{},
		},
		{
			desc: "vulnerable at and skip fix given",
			report: Report{
				Modules: []*Module{{
					Module:       "golang.org/x/vulndb",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "golang.org/x/vulndb/internal/lint",
						Symbols: []string{"Foo"},
						SkipFix: "reason given",
					}},
				}},
				Description: "description",
			},
			want: []string{},
		},
		{
			desc: "third party: module is not a prefix of package",
			report: Report{
				Modules: []*Module{{
					Module:       "golang.org/x/vulndb",
					VulnerableAt: "1.2.3",
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
					Module:       "invalid.",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "invalid.",
					}},
				}},
				Description: "description",
			},
			want: []string{"malformed import path"},
		},
		{
			desc: "standard library: missing package",
			report: Report{
				Modules: []*Module{{
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						// no package
						Symbols: []string{"Atoi"},
					}},
				}},
				Description: "description",
				References:  validStdLibReferences,
			},
			want: []string{"missing package"},
		},
		{
			desc: "toolchain: wrong module",
			report: Report{
				Modules: []*Module{{
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "cmd/go",
					}},
				}},
				Description: "description",
				References:  validStdLibReferences,
			},
			want: []string{`should be in module "cmd", not "std"`},
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
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				References:  validStdLibReferences,
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
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				References:  validStdLibReferences,
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
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				References:  validStdLibReferences,
			},
			want: []string{`invalid semantic version: "1.3.X"`},
		},
		{
			desc: "bad cve identifier",
			report: Report{
				Modules: []*Module{{
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEs:        []string{"CVE.12345.456"},
				References:  validStdLibReferences,
			},
			want: []string{"malformed cve identifier"},
		},
		{
			desc: "cve and cve metadata both present",
			report: Report{
				Modules: []*Module{{
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEs:        []string{"CVE-2022-1234545"},
				CVEMetadata: &CVEMeta{
					ID:  "CVE-2022-23456",
					CWE: "CWE 111",
				},
				References: validStdLibReferences,
			},
			want: []string{"only one of cve and cve_metadata.id should be present"},
		},
		{
			desc: "missing cve metadata required fields",
			report: Report{
				Modules: []*Module{{
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEMetadata: &CVEMeta{
					// no id
					// no cwe
				},
				References: validStdLibReferences,
			},
			want: []string{"cve_metadata.id is required", "cve_metadata.cwe is required"},
		},
		{
			desc: "bad cve metadata id",
			report: Report{
				Modules: []*Module{{
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				CVEMetadata: &CVEMeta{
					ID:  "CVE.2022.00000",
					CWE: "CWE 111",
				},
				References: validStdLibReferences,
			},
			want: []string{"malformed cve_metadata.id identifier"},
		},
		{
			desc: "invalid reference type",
			report: Report{
				Modules: []*Module{{
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				References: append([]*Reference{{
					Type: "INVALID",
					URL:  "http://go.dev/",
				}}, validStdLibReferences...),
			},
			want: []string{"not a valid reference type"},
		},
		{
			desc: "multiple advisory links",
			report: validXReport(func(r *Report) {
				r.References = append(r.References, &Reference{
					Type: "ADVISORY",
					URL:  "http://go.dev/a",
				}, &Reference{
					Type: "ADVISORY",
					URL:  "http://go.dev/b",
				})
			}),
			want: []string{"at most one advisory link"},
		},
		{
			desc: "redundant advisory links",
			report: validXReport(func(r *Report) {
				r.CVEs = []string{"CVE-0000-0000", "CVE-0000-0001"}
				r.GHSAs = []string{"GHSA-0000-0000-0000"}
				r.References = append(r.References, &Reference{
					Type: "WEB",
					URL:  "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-0000-0000",
				}, &Reference{
					Type: "WEB",
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-0000-0001",
				}, &Reference{
					Type: "WEB",
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-0000-0002", // ok
				}, &Reference{
					Type: "WEB",
					URL:  "https://github.com/advisories/GHSA-0000-0000-0000",
				}, &Reference{
					Type: "WEB",
					URL:  "https://github.com/advisories/GHSA-0000-0000-0001", // ok
				})
			}),
			want: []string{
				"redundant non-advisory reference to CVE-0000-0000",
				"redundant non-advisory reference to CVE-0000-0001",
				"redundant non-advisory reference to GHSA-0000-0000-0000",
			},
		},
		{
			desc: "unfixed links",
			report: Report{
				Modules: []*Module{{
					Module:       "golang.org/x/vulndb",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "golang.org/x/vulndb",
					}},
				}},
				Description: "description",
				References: []*Reference{
					{Type: osv.ReferenceTypeFix, URL: "https://github.com/golang/go/commit/12345"},
					{Type: osv.ReferenceTypeReport, URL: "https://github.com/golang/go/issues/12345"},
					{Type: osv.ReferenceTypeWeb, URL: "https://golang.org/xxx"},
					{Type: osv.ReferenceTypeWeb, URL: "https://groups.google.com/forum/#!/golang-announce/12345/1/"},
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
					Module:       "std",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "time",
					}},
				}},
				Description: "description",
				References: []*Reference{
					{Type: osv.ReferenceTypeFix, URL: "https://go-review.googlesource.com/c/go/+/12345"},
					{Type: osv.ReferenceTypeFix, URL: "https://github.com/golang/go/commit/12345"},
					{Type: osv.ReferenceTypeReport, URL: "https://github.com/golang/go/issues/12345"},
					{Type: osv.ReferenceTypeWeb, URL: "https://go.dev/"},
					// no announce link
				},
			},
			want: []string{
				// Standard library specific errors.
				"fix reference should match",
				"report reference should match",
				"references should contain an announcement link",
				"web references should only contain announcement links",
				// Unfixed link errors.
				`"https://github.com/golang/go/commit/12345" should be "https://go.googlesource.com/+/12345"`,
				`"https://github.com/golang/go/issues/12345" should be "https://go.dev/issue/12345"`,
			},
		},
		{
			desc: "invalid URL",
			report: Report{
				Modules: []*Module{{
					Module:       "golang.org/x/vulndb",
					VulnerableAt: "1.2.3",
					Packages: []*Package{{
						Package: "golang.org/x/vulndb",
					}},
				}},
				Description: "description",
				References: []*Reference{
					{
						Type: osv.ReferenceTypeFix,
						URL:  "go.dev/cl/12345", // needs "https://" prefix
					},
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
		test := test
		t.Run(test.desc, func(t *testing.T) {
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
				t.Errorf("missing expected lint errors in report:\n"+
					"%v\n"+
					"got:  %q\n"+
					"want: %q\n", buf.String(), got, missing)
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
					t.Errorf("unexpected lint errors in report:\n"+
						"%v\n"+
						"got:  %q\n", buf.String(), unexpected)
				}
			}
		})
	}
}
func TestFindModuleFromPackage(t *testing.T) {
	if !*proxy {
		t.Skip("no -proxy flag")
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "escape package",
			path: "k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server",
			want: "k8s.io/kubernetes/staging/src/k8s.io/apiserver",
		},
		{
			name: "no change required",
			path: "k8s.io/kubernetes/staging/src/k8s.io/apiserver",
			want: "k8s.io/kubernetes/staging/src/k8s.io/apiserver",
		},
		{
			name: "no viable module found (stdlib)",
			path: "std/net",
			want: "std/net",
		},
		{
			name: "no viable module found (third party lib)",
			path: "example.co.io/module/package/src/versions/v8",
			want: "example.co.io/module/package/src/versions/v8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FindModuleFromPackage(tt.path); got != tt.want {
				t.Errorf("FindModuleFromPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}
