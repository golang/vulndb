// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/osv"
)

func TestGenerateOSVEntry(t *testing.T) {
	r := &Report{
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
		Credit:      "gopherbot",
		References: []*Reference{
			{Type: ReferenceTypeAdvisory, URL: "advisory"},
			{Type: ReferenceTypeReport, URL: "issue"},
			{Type: ReferenceTypeFix, URL: "fix"},
			{Type: ReferenceTypeWeb, URL: "web"},
		},
	}

	wantEntry := osv.Entry{
		SchemaVersion: schemaVersion,
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
				Package: osv.Package{
					Name:      "example.com/vulnerable/v2",
					Ecosystem: "Go",
				},
				Ranges: []osv.AffectsRange{
					{
						Type: osv.TypeSemver,
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
				DatabaseSpecific: osv.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/GO-1991-0001"},
				EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{
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
				Package: osv.Package{
					Name:      "vanity.host/vulnerable",
					Ecosystem: "Go",
				},
				Ranges: []osv.AffectsRange{
					{
						Type: osv.TypeSemver,
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
				DatabaseSpecific: osv.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/GO-1991-0001"},
				EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{
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
				Package: osv.Package{
					Name:      "example.com/also-vulnerable",
					Ecosystem: "Go",
				},
				Ranges: []osv.AffectsRange{
					{
						Type: osv.TypeSemver,
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
				DatabaseSpecific: osv.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/GO-1991-0001"},
				EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{
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
	}

	gotEntry := r.GenerateOSVEntry("GO-1991-0001", time.Time{})
	if diff := cmp.Diff(wantEntry, gotEntry, cmp.Comparer(func(a, b time.Time) bool { return a.Equal(b) })); diff != "" {
		t.Errorf("GenerateOSVEntry returned unexpected entry (-want +got):\n%s", diff)
	}
}

func TestGetOSVFilename(t *testing.T) {
	want := "data/osv/GO-1999-0001.json"
	if got := GetOSVFilename("GO-1999-0001"); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestSemverCanonicalize(t *testing.T) {
	in := []VersionRange{
		{
			Introduced: "1.16.0",
			Fixed:      "1.17.0",
		},
	}
	expected := osv.Affects{
		{
			Type: osv.TypeSemver,
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

func TestTrimWhitespace(t *testing.T) {
	s := "\n Lorem ipsum dolor sit amet,\n consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n\nUt enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. \n \tDuis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. \n\n\nExcepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\n"
	want := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n\nUt enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.\n\nExcepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
	got := trimWhitespace(s)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("removeNewlines() mismatch (-want, +got):\n%s", diff)
	}
}
