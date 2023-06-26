// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/osv"
)

func TestToOSV(t *testing.T) {
	r := &Report{
		ID: "GO-1991-0001",
		Modules: []*Module{
			{
				Module: "example.com/vulnerable/v2",
				Versions: []VersionRange{
					{Fixed: "2.1.1"},
					{Introduced: "2.3.4", Fixed: "2.3.5"},
					{Introduced: "2.5.0"},
				},
				Packages: []*Package{
					{
						Package:        "example.com/vulnerable/v2",
						GOOS:           []string{"windows"},
						GOARCH:         []string{"arm64"},
						Symbols:        []string{"A", "B.b"},
						DerivedSymbols: []string{"D"},
					},
				},
			}, {
				Module: "vanity.host/vulnerable",
				Versions: []VersionRange{
					{Fixed: "2.1.1"},
					{Introduced: "2.3.4", Fixed: "2.3.5"},
					{Introduced: "2.5.0"},
				},
				Packages: []*Package{
					{
						Package: "vanity.host/vulnerable/package",
						GOOS:    []string{"windows"},
						GOARCH:  []string{"arm64"},
						Symbols: []string{"A.b", "b"},
					},
				},
			}, {
				Module: "example.com/also-vulnerable",
				Versions: []VersionRange{
					{Fixed: "2.1.1"},
				},
				Packages: []*Package{
					{
						Package: "example.com/also-vulnerable/package",
						GOOS:    []string{"windows"},
						GOARCH:  []string{"arm64"},
						Symbols: []string{"z"},
					},
				},
			},
		},
		Description: "It's a real bad one, \nI'll tell you that.\n\n More info.\n",
		CVEs:        []string{"CVE-0000-0000"},
		GHSAs:       []string{"GHSA-abcd-efgh"},
		Credits:     []string{"gopherbot"},
		References: []*Reference{
			{Type: osv.ReferenceTypeAdvisory, URL: "advisory"},
			{Type: osv.ReferenceTypeReport, URL: "issue"},
			{Type: osv.ReferenceTypeFix, URL: "fix"},
			{Type: osv.ReferenceTypeWeb, URL: "web"},
		},
	}

	wantEntry := osv.Entry{
		SchemaVersion: SchemaVersion,
		ID:            "GO-1991-0001",
		Details:       "It's a real bad one, I'll tell you that.\n\nMore info.",
		References: []osv.Reference{
			{Type: "ADVISORY", URL: "advisory"},
			{Type: "REPORT", URL: "issue"},
			{Type: "FIX", URL: "fix"},
			{Type: "WEB", URL: "web"},
		},
		Aliases: []string{"CVE-0000-0000", "GHSA-abcd-efgh"},
		Affected: []osv.Affected{
			{
				Module: osv.Module{
					Path:      "example.com/vulnerable/v2",
					Ecosystem: "Go",
				},
				Ranges: []osv.Range{
					{
						Type: osv.RangeTypeSemver,
						Events: []osv.RangeEvent{
							{
								Introduced: "0",
							},
							{
								Fixed: "2.1.1",
							},
							{
								Introduced: "2.3.4",
							},
							{
								Fixed: "2.3.5",
							},
							{
								Introduced: "2.5.0",
							},
						},
					},
				},
				EcosystemSpecific: &osv.EcosystemSpecific{
					Packages: []osv.Package{
						{
							Path:    "example.com/vulnerable/v2",
							GOOS:    []string{"windows"},
							GOARCH:  []string{"arm64"},
							Symbols: []string{"A", "B.b", "D"},
						},
					},
				},
			},
			{
				Module: osv.Module{
					Path:      "vanity.host/vulnerable",
					Ecosystem: "Go",
				},
				Ranges: []osv.Range{
					{
						Type: osv.RangeTypeSemver,
						Events: []osv.RangeEvent{
							{
								Introduced: "0",
							},
							{
								Fixed: "2.1.1",
							},
							{
								Introduced: "2.3.4",
							},
							{
								Fixed: "2.3.5",
							},
							{
								Introduced: "2.5.0",
							},
						},
					},
				},
				EcosystemSpecific: &osv.EcosystemSpecific{
					Packages: []osv.Package{
						{
							Path:    "vanity.host/vulnerable/package",
							GOOS:    []string{"windows"},
							GOARCH:  []string{"arm64"},
							Symbols: []string{"A.b", "b"},
						},
					},
				},
			},
			{
				Module: osv.Module{
					Path:      "example.com/also-vulnerable",
					Ecosystem: "Go",
				},
				Ranges: []osv.Range{
					{
						Type: osv.RangeTypeSemver,
						Events: []osv.RangeEvent{
							{
								Introduced: "0",
							},
							{
								Fixed: "2.1.1",
							},
						},
					},
				},
				EcosystemSpecific: &osv.EcosystemSpecific{
					Packages: []osv.Package{
						{
							Path:    "example.com/also-vulnerable/package",
							GOOS:    []string{"windows"},
							GOARCH:  []string{"arm64"},
							Symbols: []string{"z"},
						},
					},
				},
			},
		},
		Credits: []osv.Credit{
			{
				Name: "gopherbot",
			},
		},
		DatabaseSpecific: &osv.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/GO-1991-0001"},
	}

	gotEntry := r.ToOSV(time.Time{})
	if diff := cmp.Diff(wantEntry, gotEntry, cmp.Comparer(func(a, b time.Time) bool { return a.Equal(b) })); diff != "" {
		t.Errorf("ToOSV() mismatch (-want +got):\n%s", diff)
	}
}

func TestOSVFilename(t *testing.T) {
	want := filepath.FromSlash("data/osv/GO-1999-0001.json")
	r := &Report{ID: "GO-1999-0001"}
	if got := r.OSVFilename(); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestAffectedRanges(t *testing.T) {
	in := []VersionRange{
		{
			Introduced: "1.16.0",
			Fixed:      "1.17.0",
		},
	}
	expected := []osv.Range{
		{
			Type: osv.RangeTypeSemver,
			Events: []osv.RangeEvent{
				{
					Introduced: "1.16.0",
				},
				{
					Fixed: "1.17.0",
				},
			},
		},
	}

	out := AffectedRanges(in)
	if !reflect.DeepEqual(out, expected) {
		t.Fatalf("unexpected output: got %#v, want %#v", out, expected)
	}
}

func TestToParagraphs(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{{
		name: "empty",
		in:   "",
		want: "",
	},
		{
			name: "extra spaces",
			in: `
The first paragraph
is split into multiple lines.

   

The second paragraph
	  contains tabs 	and multiple lines    and extra spaces.
`,
			want: `The first paragraph is split into multiple lines.

The second paragraph contains tabs and multiple lines and extra spaces.`,
		},
		{
			name: "markdown elements preserved",
			in: `Hello


* A point
* Point 2

- A different list
- Another

	1. Numbered with tab
	2. More numbered
10. Multi-digit numbered

 1) Different numbering style with leading space

+ Plus sign
+ Another one 

A separate paragraph containing inline list 1) and elements that might look like Markdown:
1,
2, 
3
--flag
++i`,
			want: `Hello

* A point
* Point 2

- A different list
- Another

1. Numbered with tab
2. More numbered
10. Multi-digit numbered

1) Different numbering style with leading space

+ Plus sign
+ Another one

A separate paragraph containing inline list 1) and elements that might look like Markdown: 1, 2, 3 --flag ++i`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := toParagraphs(tc.in)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("toParagraphs() mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
