// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/test"
)

var (
	update    = flag.Bool("update", false, "update golden files")
	realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")
)

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
			VulnerableAt: VulnerableAt("1.2.3"),
			Packages: []*Package{{
				Package: "golang.org/x/net/http2",
			}},
		}},
		Description:  "description",
		Summary:      "A summary of the issue in golang.org/x/net",
		CVEs:         []string{"CVE-1234-0000"},
		ReviewStatus: Reviewed,
	}
	f(&r)
	return r
}

func validStdReport(f func(r *Report)) Report {
	r := Report{
		ID: "GO-0000-0000",
		Modules: []*Module{{
			Module:       "std",
			VulnerableAt: VulnerableAt("1.2.3"),
			Packages: []*Package{{
				Package: "net/http",
			}},
		}},
		Description:  "description",
		Summary:      "A summary of the problem with net/http",
		References:   validStdLibReferences,
		ReviewStatus: Reviewed,
	}
	f(&r)
	return r
}

func validExcludedReport(f func(r *Report)) Report {
	r := Report{
		ID:       "GO-0000-0000",
		Excluded: ExcludedNotGoCode,
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

	for _, test := range []lintTC{
		{
			name: "module_version_ok",
			desc: "Module-version pairs that exist are OK.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "golang.org/x/net",
					Versions: Versions{
						Introduced("0.2.0"),
					}})
			}),
			pc: pc,
			// No lints.
		},
		{
			name: "module_version_invalid",
			desc: "Version@module must exist.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "golang.org/x/net",
					Versions: Versions{
						Introduced("0.2.5"), // does not exist
					}})
			}),
			pc:           pc,
			wantNumLints: 1,
		},
		{
			name: "module_non_canonical",
			desc: "Module names must be canonical.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "github.com/golang/vuln",
					Versions: Versions{

						Introduced("0.1.0"),
					}})
			}),
			pc:           pc,
			wantNumLints: 1,
		},
		{
			name: "multiple_problems",
			desc: "A test for a report with multiple module-version issues at once.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "github.com/golang/vuln",
					Versions: Versions{
						Introduced("0.1.0"),
						Fixed("0.2.5"),      // does not exist
						Introduced("0.2.6"), // does not exist
					}})
			}),
			pc:           pc,
			wantNumLints: 1,
		},
		{
			name:         "no_proxy_client",
			desc:         "A non-nil proxy client must be provided.",
			report:       validReport(noop),
			pc:           nil,
			wantNumLints: 1,
		},
		{
			name: "bad_module_skip_lint",
			desc: "Module does not exist but skip lint is set.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module:   "golang.org/x/doesnotexist",
					SkipLint: true,
				})
			}),
			pc: pc,
			// No lints.
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			got := test.report.Lint(test.pc)
			updateAndCheckGolden(t, &test, got)
		})
	}
}

// lintTC is a lint test case.
type lintTC struct {
	name, desc   string
	report       Report
	pc           *proxy.Client
	wantNumLints int
}

func TestLintOffline(t *testing.T) {
	for _, test := range []lintTC{
		{
			name: "no_ID",
			desc: "All reports must have an ID.",
			report: validReport(func(r *Report) {
				r.ID = ""
			}),
			wantNumLints: 1,
		},
		{
			name: "no_modules",
			desc: "All reports (except excluded reports marked NOT_GO_CODE) must have at least one module.",
			report: validReport(func(r *Report) {
				r.Modules = nil
			}),
			wantNumLints: 1,
		},
		{
			name: "no_module_path",
			desc: "Every module must have a path.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					// no path
				})
			}),
			wantNumLints: 1,
		},
		{
			name: "no_advisory",
			desc: "Reports without a description must have an advisory link.",
			report: validReport(func(r *Report) {
				r.Description = ""
				r.References = nil
			}),
			wantNumLints: 1,
		},
		{
			name: "no_advisory_unreviewed",
			desc: "Unreviewed reports must have an advisory link.",
			report: validReport(func(r *Report) {
				r.ReviewStatus = Unreviewed
				r.References = nil
			}),
			wantNumLints: 1,
		},
		{
			name: "no_description_ok",
			desc: "Reports with no description are OK if they have an advisory.",
			report: validReport(func(r *Report) {
				r.Description = ""
				r.References = []*Reference{
					{Type: osv.ReferenceTypeAdvisory, URL: "https://example.com"},
				}
			}),
			wantNumLints: 0,
		},
		{
			name: "no_description_go_cve",
			desc: "Reports with a CVE assigned by the Go CNA must have a description.",
			report: validReport(func(r *Report) {
				r.Description = ""
				r.CVEs = nil
				r.CVEMetadata = validCVEMetadata
			}),
			wantNumLints: 1,
		},
		{
			name: "description_line_length",
			desc: "Descriptions must not (except in special cases) contain lines longer than 80 characters.",
			report: validReport(func(r *Report) {
				r.Description = "This line is too long; it needs to be shortened to less than 80 characters to pass the lint check"
			}),
			wantNumLints: 1,
		},
		{
			name: "description_long_word_ok",
			desc: "Descriptions may contain lines longer than 80 characters if the line is a single word.",
			report: validReport(func(r *Report) {
				r.Description = "http://1234567890.abcdefghijklmnopqrstuvwxyz.1234567890.abcdefghijklmnopqrstuvwxyz" // 82 chars ok if single word
			}),
			// No lints.
		},
		{
			name: "no_summary",
			desc: "Regular (non-excluded) reports must have a summary.",
			report: validReport(func(r *Report) {
				r.Summary = ""
			}),
			wantNumLints: 1,
		},
		{
			name: "no_review_status",
			desc: "Regular (non-excluded) reports must have a review status.",
			report: validReport(func(r *Report) {
				r.ReviewStatus = 0
				// add an advisory to avoid the "no advisory" lint error
				r.References = []*Reference{
					{
						URL:  idstr.AdvisoryLink("CVE-1234-0000"),
						Type: osv.ReferenceTypeAdvisory,
					},
				}
			}),
			wantNumLints: 1,
		},
		{
			name: "summary_todo",
			desc: "Summaries must not contain TODOs.",
			report: validReport(func(r *Report) {
				r.Summary = "TODO: fill this out"
			}),
			wantNumLints: 1,
		},
		{
			name: "summary_too_long",
			desc: fmt.Sprintf("The summary must be %d characters or less.", summaryMaxLen),
			report: validReport(func(r *Report) {
				r.Summary = Summary(
					fmt.Sprintf("This summary of golang.org/x/net is too long and probably has unnecessary detail; it needs to be shortened to %d or fewer characters to pass the lint check", summaryMaxLen),
				)
			}),
			wantNumLints: 1,
		},
		{
			name: "summary_period",
			desc: "The summary should not end in a period. It should be a phrase, not a sentence.",
			report: validReport(func(r *Report) {
				r.Summary = "This summary of golang.org/x/net is a sentence, not a phrase."
			}),
			wantNumLints: 1,
		},
		{
			name: "summary_no_path",
			desc: "The summary must contain a module or package path listed in the report.",
			report: validReport(func(r *Report) {
				r.Summary = "This summary doesn't have a path"
			}),
			wantNumLints: 1,
		},
		{
			name: "summary_path_prefix",
			desc: "Summary may contain a prefix of a module or package path that is mentioned at least twice in a report. This is a workaround for reports that affect many modules.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module:       "example.com/module/example/v2",
					VulnerableAt: VulnerableAt("1.0.0"),
				})
				r.Modules = append(r.Modules, &Module{
					Module:       "example.com/module/example/v3",
					VulnerableAt: VulnerableAt("1.0.0"),
				})
				r.Summary = "This summary is about example.com/module/example"
			}),
			// No lints.
		},
		{
			name: "summary_ok_unreviewed",
			desc: "Summary does not need to conform to style guide for unreviewed reports.",
			report: validReport(func(r *Report) {
				r.ReviewStatus = Unreviewed
				// add an advisory to avoid the "no advisory" lint error
				r.References = []*Reference{
					{
						URL:  idstr.AdvisoryLink("CVE-1234-0000"),
						Type: osv.ReferenceTypeAdvisory,
					},
				}
				r.Summary = "this summary doesn't conform to our `style` guide, but its ok because this is an unreviewed report."
			}),
			// No lints.
		},
		{
			name: "no_package_path",
			desc: "All packages must have a path.",
			report: validReport(func(r *Report) {
				r.Modules[0].Packages = append(r.Modules[0].Packages,
					&Package{
						// No package path.
					})
			}),
			wantNumLints: 1,
		},
		{
			name: "no_vulnerable_at_or_skip_fix",
			desc: "At least one of module.vulnerable_at and module.package.skip_fix must be set.",
			report: validReport(func(r *Report) {
				r.Modules[0].VulnerableAt = nil
				r.Modules[0].Packages[0].SkipFixSymbols = ""
			}),
			wantNumLints: 1,
		},
		{
			name: "skip_fix_ok",
			desc: "The vulnerable_at field can be blank if skip_fix is set.",
			report: validReport(func(r *Report) {
				r.Modules[0].VulnerableAt = nil
				r.Modules[0].Packages[0].SkipFixSymbols = "a reason"
			}),
			// No lints.
		},
		{
			name: "vulnerable_at_and_skip_fix_ok",
			desc: "It is OK to set both module.vulnerable_at and module.package.skip_fix.",
			report: validReport(func(r *Report) {
				r.Modules[0].VulnerableAt = VulnerableAt("1.2.3")
				r.Modules[0].Packages[0].SkipFixSymbols = "a reason"
			}),
			// No lints.
		},
		{
			name: "vulnerable_at_out_of_range",
			desc: "Field module.vulnerable_at must be inside the vulnerable version range for the module.",
			report: validStdReport(func(r *Report) {
				r.Modules[0].VulnerableAt = VulnerableAt("2.0.0")
				r.Modules[0].Versions = Versions{
					Fixed("1.2.1"),
				}
			}),
			wantNumLints: 1,
		},
		{
			name: "unsupported_versions",
			desc: "The unsupported_versions field should never be set.",
			report: validStdReport(func(r *Report) {
				r.Modules[0].UnsupportedVersions = Versions{
					{Version: "1.2.1", Type: "unknown"},
				}
			}),
			wantNumLints: 1,
		},
		{
			name: "module_package_prefix",
			desc: "In third party reports, module names must be prefixes of package names.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module:       "example.com/module",
					VulnerableAt: VulnerableAt("1.0.0"),
					Packages: []*Package{{
						Package: "example.com/package",
					}},
				})
			}),
			wantNumLints: 1,
		},
		{
			name: "invalid_package_path",
			desc: "In third party reports, package paths must pass validity checks in x/mod/module.CheckImportPath.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module:       "invalid.",
					VulnerableAt: VulnerableAt("1.0.0"),
					Packages: []*Package{{
						Package: "invalid.",
					}}})
			}),
			wantNumLints: 1,
		},
		{
			name: "no_package_path_stdlib",
			desc: "All packages must have a path.",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Packages[0].Package = ""
			}),
			wantNumLints: 1,
		},
		{
			name: "no_package_stdlib",
			desc: "In standard library reports, all modules must contain at least one package.",
			report: validStdReport(func(r *Report) {
				r.Modules = append(r.Modules,
					&Module{
						Module:       "std",
						VulnerableAt: VulnerableAt("1.0.0"),
						// No packages.
					},
				)
			}),
			wantNumLints: 1,
		},
		{
			name: "runtime_package_with_symbols",
			desc: "In standard library reports, the runtime package must not contain any symbols.",
			report: validStdReport(func(r *Report) {
				r.Modules = append(r.Modules,
					&Module{
						Module:       "std",
						VulnerableAt: VulnerableAt("1.0.0"),
						Packages: []*Package{{
							Package: "runtime",
							Symbols: []string{"foo"},
						}},
					},
				)
			}),
			wantNumLints: 1,
		},
		{
			name: "wrong_module_cmd",
			desc: "Packages beginning with 'cmd' should be in the 'cmd' module.",
			report: validStdReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module:       "std",
					VulnerableAt: VulnerableAt("1.0.0"),
					Packages: []*Package{{
						Package: "cmd/go",
					}},
				})
			}),
			wantNumLints: 1,
		},
		{
			name: "versions_overlapping_ranges",
			desc: "Version ranges must not overlap.",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Versions = Versions{
					// Two fixed versions in a row with no introduced.
					Fixed("1.2.1"), Fixed("1.3.2"),
				}
			}),
			wantNumLints: 1,
		},
		{
			name: "versions_fixed_before_introduced",
			desc: "Within a version range, the fixed version must come before the introduced version.",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Versions = Versions{

					Introduced("1.3.0"),
					Fixed("1.2.1"),
				}
			}),
			wantNumLints: 1,
		},
		{
			name: "versions_checked_no_vulnerable_at",
			desc: "Version checks still apply if vulnerable_at is not set.",
			report: validStdReport(func(r *Report) {
				r.Modules[0].VulnerableAt = nil
				r.Modules[0].Versions = Versions{
					// Two fixed versions in a row with no introduced.
					Fixed("1.2.1"), Fixed("1.3.2"),
				}
			}),
			wantNumLints: 2,
		},
		{
			name: "invalid_semver",
			desc: "All versions must be valid, unprefixed, semver",
			report: validStdReport(func(r *Report) {
				r.Modules[0].Versions = Versions{
					Introduced("1.3.X"),
				}
			}),
			wantNumLints: 1,
		},
		{
			name: "bad_cve",
			desc: "All CVEs must be valid.",
			report: validReport(func(r *Report) {
				r.CVEs = []string{"CVE.1234.5678"}
			}),
			wantNumLints: 1,
		},
		{
			name: "bad_ghsa",
			desc: "All GHSAs must be valid.",
			report: validReport(func(r *Report) {
				r.GHSAs = []string{"GHSA-123"}
			}),
			wantNumLints: 1,
		},
		{
			name: "cve_and_cve_metadata_ok",
			desc: "It is OK to set both cves and cve_metadata.",
			report: validReport(func(r *Report) {
				r.CVEs = []string{"CVE-0000-1111"}
				r.CVEMetadata = validCVEMetadata
			}),
			// No lints.
		},
		{
			name: "cve_metadata_missing_fields",
			desc: "Field cve_metadata (if not nil), must have an ID and CWE.",
			report: validReport(func(r *Report) {
				r.CVEs = nil
				r.CVEMetadata = &CVEMeta{
					// missing fields
				}
			}),
			wantNumLints: 2,
		},
		{
			name: "cve_metadata_bad_fields",
			desc: "Field cve_metadata must contain valid entries for ID and CWE.",
			report: validReport(func(r *Report) {
				r.CVEs = nil
				r.CVEMetadata = &CVEMeta{
					ID:  "CVE.0000.1111",
					CWE: "TODO",
				}
			}),
			wantNumLints: 2,
		},
		{
			name: "reference_invalid_type",
			desc: "Reference type must be one of the pre-defined types in osv.ReferenceTypes.",
			report: validReport(func(r *Report) {
				r.References = append(r.References, &Reference{
					Type: "INVALID",
					URL:  "http://go.dev/",
				})
			}),
			wantNumLints: 1,
		},
		{
			name: "references_multiple_advisories",
			desc: "Each report should contain at most one advisory reference.",
			report: validReport(func(r *Report) {
				r.References = append(r.References, &Reference{
					Type: "ADVISORY",
					URL:  "http://go.dev/a",
				}, &Reference{
					Type: "ADVISORY",
					URL:  "http://go.dev/b",
				})
			}),
			wantNumLints: 1,
		},
		{
			name: "references_redundant_web_advisories",
			desc: "Reports should not contain redundant web-type references linking to CVEs/GHSAs listed in the cves/ghsas sections.",
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
			wantNumLints: 3,
		},
		{
			name: "references_unfixed",
			desc: "References should not contain non-canonical link formats (that can be auto-fixed).",
			report: validReport(func(r *Report) {
				r.References = []*Reference{
					{Type: osv.ReferenceTypeFix, URL: "https://github.com/golang/go/commit/12345"},
					{Type: osv.ReferenceTypeReport, URL: "https://github.com/golang/go/issues/12345"},
					{Type: osv.ReferenceTypeWeb, URL: "https://golang.org/xxx"},
					{Type: osv.ReferenceTypeWeb, URL: "https://groups.google.com/forum/#!/golang-announce/12345/1/"},
				}
			}),
			wantNumLints: 4,
		},
		{
			name: "references_incorrect_stdlib",
			desc: "Standard library reports must contain references matching a specific format.",
			report: validStdReport(func(r *Report) {
				r.References = []*Reference{
					{Type: osv.ReferenceTypeAdvisory, URL: "http://www.example.com"},
					{Type: osv.ReferenceTypeFix, URL: "https://go-review.googlesource.com/c/go/+/12345"},
					{Type: osv.ReferenceTypeFix, URL: "https://github.com/golang/go/commit/12345"},
					{Type: osv.ReferenceTypeReport, URL: "https://github.com/golang/go/issues/12345"},
					{Type: osv.ReferenceTypeWeb, URL: "https://go.dev/"},
					// no announce link
				}
			}),
			wantNumLints: 8,
		},
		{
			name: "references_missing_stdlib",
			desc: "Standard library reports must contain at least one report, fix, and announcement link.",
			report: validStdReport(func(r *Report) {
				r.References = []*Reference{
					// no links
				}
			}),
			wantNumLints: 3,
		},
		{
			name: "reference_invalid_URL",
			desc: "References must be valid URLs.",
			report: validReport(func(r *Report) {
				r.References = []*Reference{
					{
						Type: osv.ReferenceTypeFix,
						URL:  "go.dev/cl/12345", // needs "https://" prefix
					},
				}
			}),
			wantNumLints: 1,
		},
		{
			name: "missing_fields_excluded",
			desc: "Excluded reports must contain (at least): a valid excluded reason, a module, and one CVE or GHSA.",
			report: validExcludedReport(func(r *Report) {
				r.Excluded = "not a real reason"
				r.Modules = nil
				r.CVEs = nil
				r.GHSAs = nil
			}),
			wantNumLints: 3,
		},
		{
			name: "bad_related",
			desc: "The related field must not contain duplicate or invalid IDs.",
			report: validReport(func(r *Report) {
				r.CVEs = []string{"CVE-0000-1111"}
				r.Related = []string{
					"not-an-id",           // bad
					"CVE-0000-1111",       // bad (duplicate)
					"CVE-0000-1112",       // ok
					"GHSA-0000-0000-0000", // ok
					"GO-1990-0001",        // ok
				}
			}),
			wantNumLints: 2,
		},
		{
			name: "module_version_offline",
			desc: "In offline mode, module-version consistency is not checked because it requires a call to the module proxy.",
			report: validReport(func(r *Report) {
				r.Modules = append(r.Modules, &Module{
					Module: "golang.org/x/net",
					Versions: Versions{
						Introduced("0.2.5"), // does not exist
					},
				})
			}),
			// No lints: in offline mode, versions aren't checked.
		},
		{
			name:   "valid_excluded",
			desc:   "No lints are generated for valid excluded reports.",
			report: validExcludedReport(noop),
			// No lints.
		},
		{
			name: "markdown",
			desc: "Descriptions and summaries should not contain Markdown formatting.",
			report: validReport(
				func(r *Report) {
					r.Summary += " in function `Hello`"
					r.Description = "# Problem\nMore info [here](https://example.com)"
				},
			),
			wantNumLints: 3,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			got := test.report.LintOffline()
			updateAndCheckGolden(t, &test, got)
		})
	}
}

// The name of the "file" in the txtar archive containing the expected output.
const golden = "golden"

func updateAndCheckGolden(t *testing.T, test *lintTC, lints []string) {
	if *update {
		if errs := checkGoldenFile(t, test, lints); len(errs) == 0 {
			return
		}
		if err := updateGoldenFile(t, test, lints); err != nil {
			t.Error(err)
		}
	}
	for _, err := range checkGoldenFile(t, test, lints) {
		t.Error(err)
	}
}

func updateGoldenFile(t *testing.T, tc *lintTC, lints []string) error {
	t.Helper()

	fpath := goldenFilename(t)

	// Double-check that we got the right number of lints, to make it
	// harder to lose/gain a lint with the auto-update.
	if tc.wantNumLints != len(lints) {
		return fmt.Errorf("%s: cannot update: got %d lints, want %d", fpath, len(lints), tc.wantNumLints)
	}

	rb, err := reportToBytes(&tc.report)
	if err != nil {
		return err
	}

	return test.WriteTxtar(fpath, []txtar.File{
		{
			Name: testYAMLFilename(&tc.report),
			Data: rb,
		},
		{
			Name: golden,
			Data: lintsToBytes(lints),
		},
	}, newComment(t, tc))
}

func checkGoldenFile(t *testing.T, tc *lintTC, lints []string) []error {
	t.Helper()

	fpath := goldenFilename(t)

	if _, err := os.Stat(fpath); err != nil {
		return []error{fmt.Errorf("golden file %s does not exist (re-run test with -update flag)", fpath)}
	}

	ar, err := txtar.ParseFile(fpath)
	if err != nil {
		return []error{err}
	}

	var errs []error

	wantComment, gotComment := newComment(t, tc), string(ar.Comment)
	if err := test.CheckComment(wantComment, gotComment); err != nil {
		errs = append(errs, err)
	}

	// Check that all expected files are present and have the correct contents.
	reportFile := testYAMLFilename(&tc.report)
	foundReport, foundGolden := false, false
	for _, f := range ar.Files {
		switch af := f.Name; {
		case af == golden:
			want := f.Data
			got := lintsToBytes(lints)
			if diff := cmp.Diff(want, got); diff != "" {
				errs = append(errs, fmt.Errorf("%s: %s: mismatch (-want, +got):\n%s", fpath, af, diff))
			}
			foundGolden = true
		case af == reportFile:
			want := f.Data
			got, err := reportToBytes(&tc.report)
			if err != nil {
				t.Errorf("%s: %s", af, err)
				continue
			}
			if diff := cmp.Diff(want, got); diff != "" {
				errs = append(errs, fmt.Errorf("%s: %s: mismatch (-want, +got):\n%s", fpath, af, diff))
			}
			foundReport = true
		default:
			errs = append(errs, fmt.Errorf("%s: unexpected archive file %s, expected one of (%q, %q)", fpath, af, reportFile, golden))
		}
	}
	if !foundReport {
		errs = append(errs, fmt.Errorf("%s: no report found (want archive file %q)", fpath, reportFile))
	}
	if !foundGolden {
		errs = append(errs, fmt.Errorf("%s: no golden found (want archive file %q)", fpath, golden))
	}
	return errs
}

func testYAMLFilename(r *Report) string {
	id := r.ID
	if id == "" {
		id = "NO-GO-ID"
	}
	// Use path instead of filepath so that the paths
	// always use forward slashes.
	// These filenames are only used inside .txtar archives.
	return path.Join(dataFolder, r.folder(), id+".yaml")
}

func newComment(t *testing.T, tc *lintTC) string {
	t.Helper()
	return fmt.Sprintf("Test: %s\nDescription: %s", t.Name(), tc.desc)
}

func goldenFilename(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "lint", t.Name()+".txtar")
}

func lintsToBytes(lints []string) []byte {
	return []byte(strings.Join(lints, "\n") + "\n")
}

func reportToBytes(report *Report) ([]byte, error) {
	ys, err := report.ToString()
	if err != nil {
		return nil, err
	}
	return []byte(ys + "\n"), nil
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

func TestLintAsNotes(t *testing.T) {
	// A report with lints.
	report := validReport(
		func(r *Report) {
			r.Summary = ""
			r.Notes = []*Note{
				{Body: "an existing lint that will be deleted", Type: NoteTypeLint},
				{Body: "a note added by a human", Type: NoteTypeNone}}
		},
	)

	found := report.LintAsNotes(nil)
	if !found {
		t.Error("LintAsNotes() = false, want true")
	}

	want, got := []*Note{
		{Body: "a note added by a human", Type: NoteTypeNone}, // preserved
		{Body: "summary: missing", Type: NoteTypeLint},
		{Body: "proxy client is nil; cannot perform all lint checks", Type: NoteTypeLint}}, report.Notes
	if diff := cmp.Diff(want, got,
		// ignore order
		cmpopts.SortSlices(
			func(a, b *Note) bool {
				if a.Type < b.Type {
					return true
				} else if a.Type > b.Type {
					return false
				}
				return a.Body < b.Body
			})); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
