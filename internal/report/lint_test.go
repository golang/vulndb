// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"flag"
	"strings"
	"testing"

	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
)

var realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")

var (
	validStdLibReferences = []*Reference{
		{Type: osv.ReferenceTypeFix, URL: "https://go.dev/cl/12345"},
		{Type: osv.ReferenceTypeWeb, URL: "https://groups.google.com/g/golang-announce/c/12345"},
		{Type: osv.ReferenceTypeReport, URL: "https://go.dev/issue/12345"},
	}
	validCVEMetadata = &CVEMeta{
		ID:  "CVE-0000-1111",
		CWE: "CWE XXX: A CWE description",
	}
	noop = func(*Report) {}
)

func validReport(f func(r *Report)) Report {
	r := Report{
		ID: "GO-0000-0000",
		Modules: []*Module{{
			Module:       "golang.org/x/net",
			VulnerableAt: "1.2.3",
			Packages: []*Package{{
				Package: "golang.org/x/net/http2",
			}},
		}},
		Description: "description",
		Summary:     "a summary",
		CVEs:        []string{"CVE-1234-0000"},
	}
	f(&r)
	return r
}

func validStdReport(f func(r *Report)) Report {
	r := Report{
		ID: "GO-0000-0000",
		Modules: []*Module{{
			Module:       "std",
			VulnerableAt: "1.2.3",
			Packages: []*Package{{
				Package: "net/http",
			}},
		}},
		Description: "description",
		Summary:     "a summary",
		References:  validStdLibReferences,
	}
	f(&r)
	return r
}

func validExcludedReport(f func(r *Report)) Report {
	r := Report{
		ID:       "GO-0000-0000",
		Excluded: "NOT_GO_CODE",
		CVEs:     []string{"CVE-2022-1234545"},
	}
	f(&r)
	return r
}

func TestLint(t *testing.T) {
	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		desc   string
		report Report
		want   []string
	}{
		{
			desc: "ok module-version pair",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "golang.org/x/net",
					Versions: []VersionRange{
						{
							Introduced: "0.2.0",
						},
					}})
			}),
			// No lints.
		},
		{
			desc: "invalid module-version pair",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "golang.org/x/net",
					Versions: []VersionRange{
						{
							Introduced: "0.2.5", // does not exist
						},
					}})
			}),
			want: []string{`version 0.2.5 does not exist`},
		},
		{
			desc: "non-canonical module",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "github.com/golang/vuln",
					Versions: []VersionRange{
						{
							Introduced: "0.1.0",
						},
					}})
			}),
			want: []string{`module is not canonical`},
		},
	} {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			got := test.report.Lint(pc)
			checkLints(t, got, test.want)
		})
	}
}

func TestLintOffline(t *testing.T) {
	for _, test := range []struct {
		desc   string
		report Report
		want   []string
	}{
		{
			desc: "no ID",
			report: validReport(func(r *Report) {
				r.ID = ""
			}),
			want: []string{"missing ID"},
		},
		{
			desc: "no modules",
			report: validReport(func(r *Report) {
				r.Modules = nil
			}),
			want: []string{"no modules"},
		},
		{
			desc: "missing module path",
			report: validReport(func(r *Report) {
				r.Modules[0].Module = ""
			}),
			want: []string{"missing module"},
		},
		{
			desc: "missing description & advisory",
			report: validReport(func(r *Report) {
				r.Description = ""
				r.References = nil
			}),
			want: []string{"missing advisory"},
		},
		{
			desc: "missing description with advisory ok",
			report: validReport(func(r *Report) {
				r.Description = ""
				r.References = []*Reference{
					{Type: osv.ReferenceTypeAdvisory, URL: "https://example.com"},
				}
			}),
			want: nil,
		},
		{
			desc: "missing description (Go CVE)",
			report: validReport(func(r *Report) {
				r.Description = ""
				r.CVEs = nil
				r.CVEMetadata = validCVEMetadata
			}),
			want: []string{"missing description"},
		},
		{
			desc: "missing summary",
			report: validReport(func(r *Report) {
				r.Summary = ""
			}),
			want: []string{"missing summary"},
		},
		{
			desc: "summary has TODO",
			report: validReport(func(r *Report) {
				r.Summary = "TODO: fill this out"
			}),
			want: []string{"summary contains a TODO"},
		},
		{
			desc: "summary too long",
			report: validReport(func(r *Report) {
				r.Summary = "This summary is too long; it needs to be shortened to less than 101 characters to pass the lint check"
			}),
			want: []string{"too long"},
		},
		{
			desc: "summary ending in period",
			report: validReport(func(r *Report) {
				r.Summary = "This summary is a sentence, not a phrase."
			}),
			want: []string{"should not end in a period"},
		},
		{
			desc: "missing package path",
			report: validReport(func(r *Report) {
				r.Modules[0].Packages[0].Package = ""
			}),
			want: []string{"missing package"},
		},
		{
			desc: "missing vulnerable at and skip fix",
			report: validReport(func(r *Report) {
				r.Modules[0].VulnerableAt = ""
				r.Modules[0].Packages[0].SkipFix = ""
			}),
			want: []string{"missing skip_fix and vulnerable_at"},
		},
		{
			desc: "skip fix given",
			report: validReport(func(r *Report) {
				r.Modules[0].VulnerableAt = ""
				r.Modules[0].Packages[0].SkipFix = "a reason"
			}),
			want: []string{},
		},
		{
			desc: "vulnerable at and skip fix given",
			report: validReport(func(r *Report) {
				r.Modules[0].VulnerableAt = "1.2.3"
				r.Modules[0].Packages[0].SkipFix = "a reason"
			}),
			want: []string{},
		},
		{
			desc: "vulnerable_at outside vulnerable range",
			report: validStdReport(func(r *Report) {
				r.Modules[0].VulnerableAt = "2.0.0"
				r.Modules[0].Versions = []VersionRange{
					{Fixed: "1.2.1"},
				}
			}),
			want: []string{"vulnerable_at version 2.0.0 is not inside vulnerable range"},
		},
		{
			desc: "third party: module is not a prefix of package",
			report: validReport(func(r *Report) {
				r.Modules[0].Module = "example.com/module"
				r.Modules[0].Packages[0].Package = "example.com/package"
			}),
			want: []string{"module must be a prefix of package"},
		},
		{
			desc: "third party: invalid import path",
			report: validReport(func(r *Report) {
				r.Modules[0].Module = "invalid."
				r.Modules[0].Packages[0].Package = "invalid."
			}),
			want: []string{"malformed import path"},
		},
		{
			desc: "standard library: missing package",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Packages[0].Package = ""
			}),
			want: []string{"missing package"},
		},
		{
			desc: "toolchain: wrong module",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Module = "std"
				r.Modules[0].Packages[0].Package = "cmd/go"
			}),
			want: []string{`should be in module "cmd", not "std"`},
		},
		{
			desc: "overlapping version ranges",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Versions = []VersionRange{
					// Two fixed versions in a row with no introduced.
					{Fixed: "1.2.1"}, {Fixed: "1.3.2"},
				}
			}),
			want: []string{"introduced and fixed versions must alternate"},
		},
		{
			desc: "fixed before introduced",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Versions = []VersionRange{
					{
						Introduced: "1.3.0",
						Fixed:      "1.2.1",
					},
				}
			}),
			want: []string{`range events must be in strictly ascending order (found 1.3.0>=1.2.1)`},
		},
		{
			desc: "invalid semantic version",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Versions = []VersionRange{
					{
						Introduced: "1.3.X",
					},
				}
			}),
			want: []string{`invalid or non-canonical semver version (found 1.3.X)`},
		},
		{
			desc: "bad cve identifier",
			report: validReport(func(r *Report) {
				r.CVEs = []string{"CVE.1234.5678"}
			}),
			want: []string{"malformed cve identifier"},
		},
		{
			desc: "cve and cve metadata both present",
			report: validReport(func(r *Report) {
				r.CVEs = []string{"CVE-0000-1111"}
				r.CVEMetadata = validCVEMetadata
			}),
			want: nil,
		},
		{
			desc: "missing cve metadata required fields",
			report: validReport(func(r *Report) {
				r.CVEs = nil
				r.CVEMetadata = &CVEMeta{
					// missing fields
				}
			}),
			want: []string{"cve_metadata.id is required", "cve_metadata.cwe is required"},
		},
		{
			desc: "bad cve metadata",
			report: validReport(func(r *Report) {
				r.CVEs = nil
				r.CVEMetadata = &CVEMeta{
					ID:  "CVE.0000.1111",
					CWE: "TODO",
				}
			}),
			want: []string{"malformed cve_metadata.id identifier", "cve_metadata.cwe contains a TODO"},
		},
		{
			desc: "invalid reference type",
			report: validReport(func(r *Report) {
				r.References = append(r.References, &Reference{
					Type: "INVALID",
					URL:  "http://go.dev/",
				})
			}),
			want: []string{"not a valid reference type"},
		},
		{
			desc: "multiple advisory links",
			report: validReport(func(r *Report) {
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
			report: validReport(func(r *Report) {
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
			report: validReport(func(r *Report) {
				r.References = []*Reference{
					{Type: osv.ReferenceTypeFix, URL: "https://github.com/golang/go/commit/12345"},
					{Type: osv.ReferenceTypeReport, URL: "https://github.com/golang/go/issues/12345"},
					{Type: osv.ReferenceTypeWeb, URL: "https://golang.org/xxx"},
					{Type: osv.ReferenceTypeWeb, URL: "https://groups.google.com/forum/#!/golang-announce/12345/1/"},
				}
			}),
			want: []string{
				`"https://github.com/golang/go/issues/12345" should be "https://go.dev/issue/12345"`,
				`"https://golang.org/xxx" should be "https://go.dev/xxx"`,
				`"https://github.com/golang/go/commit/12345" should be "https://go.googlesource.com/+/12345"`,
				`"https://groups.google.com/forum/#!/golang-announce/12345/1/" should be "https://groups.google.com/g/golang-announce/c/12345/m/1/"`},
		},
		{
			desc: "standard library: unfixed/missing links",
			report: validStdReport(func(r *Report) {
				r.References = []*Reference{
					{Type: osv.ReferenceTypeFix, URL: "https://go-review.googlesource.com/c/go/+/12345"},
					{Type: osv.ReferenceTypeFix, URL: "https://github.com/golang/go/commit/12345"},
					{Type: osv.ReferenceTypeReport, URL: "https://github.com/golang/go/issues/12345"},
					{Type: osv.ReferenceTypeWeb, URL: "https://go.dev/"},
					// no announce link
				}
			}),
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
			report: validReport(func(r *Report) {
				r.References = []*Reference{
					{
						Type: osv.ReferenceTypeFix,
						URL:  "go.dev/cl/12345", // needs "https://" prefix
					},
				}
			}),
			want: []string{
				`"go.dev/cl/12345" is not a valid URL`,
			},
		},
		{
			desc: "excluded missing/incorrect fields",
			report: validExcludedReport(func(r *Report) {
				r.Excluded = "not a real reason"
				r.Modules = nil
				r.CVEs = nil
				r.GHSAs = nil
			}),
			want: []string{
				"not a valid excluded reason",
				"no modules",
				"excluded report must have at least one associated CVE or GHSA",
			},
		},
		{
			desc: "invalid module-version pair ignored",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "golang.org/x/net",
					Versions: []VersionRange{
						{
							Introduced: "0.2.5", // does not exist
						},
					}})
			}),
			// No lints: in offline mode, versions aren't checked.
		},
		{
			desc:   "valid excluded",
			report: validExcludedReport(noop),
			// No lints.
		},
	} {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			got := test.report.LintOffline()
			checkLints(t, got, test.want)
		})
	}
}

func checkLints(t *testing.T, got, want []string) {
	var missing []string
	for _, w := range want {
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
		t.Errorf("missing expected lint errors in report:\n"+
			"got:  %q\n"+
			"want: %q\n", got, missing)
	}

	// Check for unexpected lint errors if there are no missing ones.
	if len(missing) == 0 {
		var unexpected []string
		for _, g := range got {
			found := false
			for _, w := range want {
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
			t.Errorf("unexpected lint errors in report:\n"+
				"got:  %q\n", unexpected)
		}
	}
}

func TestCheckFilename(t *testing.T) {
	for _, test := range []struct {
		desc     string
		filename string
		report   Report
		wantErr  error
	}{
		{
			desc:     "wrong ID",
			filename: "data/reports/GO-0000-0000.yaml",
			report: validReport(
				func(r *Report) {
					r.ID = "GO-0000-1111"
				}),
			wantErr: errWrongID,
		},
		{
			desc:     "excluded in correct directory",
			filename: "data/excluded/GO-0000-0000.yaml",
			report:   validExcludedReport(noop),
			wantErr:  nil,
		},
		{
			desc:     "excluded in wrong directory",
			filename: "data/wrong/GO-0000-0000.yaml",
			report:   validExcludedReport(noop),
			wantErr:  errWrongDir,
		},
		{
			desc:     "non-excluded in correct directory",
			filename: "data/reports/GO-0000-0000.yaml",
			report:   validReport(noop),
			wantErr:  nil,
		},
		{
			desc:     "non-excluded in wrong directory",
			filename: "data/wrong/GO-0000-0000.yaml",
			report:   validReport(noop),
			wantErr:  errWrongDir,
		},
	} {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			if err := test.report.CheckFilename(test.filename); !errors.Is(err, test.wantErr) {
				t.Errorf("CheckFilename(%s) = %v, want error %v", test.filename, err, test.wantErr)
			}
		})
	}
}
