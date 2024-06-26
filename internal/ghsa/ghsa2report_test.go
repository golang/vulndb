// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ghsa

import (
	"flag"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var (
	realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")
)

var testTime = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)

func TestGHSAToReport(t *testing.T) {
	updatedTime := time.Date(2022, 01, 01, 01, 01, 00, 00, time.UTC)
	sa := &SecurityAdvisory{
		ID:          "G1_blah",
		Identifiers: []Identifier{{Type: "GHSA", Value: "G1"}, {Type: "CVE", Value: "C1"}},
		UpdatedAt:   updatedTime,
		Permalink:   "https://github.com/permalink/to/G1",
		Description: "a description",
		Vulns: []*Vuln{{
			Package:                "golang.org/x/tools/go/packages",
			EarliestFixedVersion:   "0.9.0",
			VulnerableVersionRange: "< 0.9.0",
		}},
		References: []Reference{{URL: "https://github.com/permalink/to/issue/12345"}},
	}

	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name         string
		module       string
		reviewStatus report.ReviewStatus
		want         *report.Report
	}{
		{
			name:         "module provided",
			module:       "golang.org/x/tools",
			reviewStatus: report.Reviewed,
			want: &report.Report{
				ID: report.PendingID,
				Modules: []*report.Module{{
					Module:       "golang.org/x/tools",
					VulnerableAt: report.VulnerableAt("0.8.0"),
					Versions: report.Versions{
						report.Fixed("0.9.0"),
					},
					Packages: []*report.Package{{
						Package: "golang.org/x/tools/go/packages",
					}},
				}},
				Summary:     "C1 in golang.org/x/tools",
				Description: "a description",
				GHSAs:       []string{"G1"},
				CVEs:        []string{"C1"},
				References:  []*report.Reference{{Type: "REPORT", URL: "https://github.com/permalink/to/issue/12345"}},
				SourceMeta: &report.SourceMeta{
					ID:      "G1_blah",
					Created: &testTime,
				},
				ReviewStatus: report.Reviewed,
			},
		},
		{
			name:         "empty module attempts to find module from package",
			module:       "",
			reviewStatus: report.Reviewed,
			want: &report.Report{
				ID: report.PendingID,
				Modules: []*report.Module{{
					Module: "golang.org/x/tools",
					Versions: report.Versions{
						report.Fixed("0.9.0"),
					},
					VulnerableAt: report.VulnerableAt("0.8.0"),
					Packages: []*report.Package{{
						Package: "golang.org/x/tools/go/packages",
					},
						{
							Package: "golang.org/x/tools/go/packages",
						}},
				}},
				Summary:     "C1 in golang.org/x/tools",
				Description: "a description",
				GHSAs:       []string{"G1"},
				CVEs:        []string{"C1"},
				References:  []*report.Reference{{Type: "REPORT", URL: "https://github.com/permalink/to/issue/12345"}},
				SourceMeta: &report.SourceMeta{
					ID:      "G1_blah",
					Created: &testTime,
				},
				ReviewStatus: report.Reviewed,
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			got := report.New(sa, pc, report.WithModulePath(test.module),
				report.WithCreated(testTime), report.WithReviewStatus(test.reviewStatus))
			if diff := cmp.Diff(*got, *test.want); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
func TestParseVulnRange(t *testing.T) {
	for _, test := range []struct {
		in   string
		want []vulnRangeItem
	}{
		{"", nil},
		{"< 1.2.3", []vulnRangeItem{{"<", "1.2.3"}}},
		{"< 4.3.2, >= 1.2.3", []vulnRangeItem{
			{"<", "4.3.2"},
			{">=", "1.2.3"},
		}},
	} {
		got, err := parseVulnRange(test.in)
		if err != nil {
			t.Fatal(err)
		}
		if !cmp.Equal(got, test.want, cmp.AllowUnexported(vulnRangeItem{})) {
			t.Errorf("%q:\ngot  %+v\nwant %+v", test.in, got, test.want)
		}
	}
}

func TestVersions(t *testing.T) {
	for _, test := range []struct {
		earliestFixed string
		vulnRange     string
		want          report.Versions
	}{
		{"1.0.0", "< 1.0.0", report.Versions{report.Fixed("1.0.0")}},
		{"", "<= 1.4.2", nil},
		{
			"1.1.3", ">= 1.1.0, < 1.1.3",
			report.Versions{report.Introduced("1.1.0"), report.Fixed("1.1.3")},
		},
		{
			"1.2.3", "<= 2.3.4",
			report.Versions{report.Introduced(`TODO (earliest fixed "1.2.3", vuln range "<= 2.3.4")`)},
		},
	} {
		got := versions(test.earliestFixed, test.vulnRange)
		want := test.want
		if !cmp.Equal(got, want) {
			t.Errorf("%q, %q:\ngot  %+v\nwant %+v",
				test.earliestFixed, test.vulnRange, got, want)
		}
	}
}
