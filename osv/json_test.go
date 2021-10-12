// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osv

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/report"
)

func TestGenerate(t *testing.T) {
	r := report.Report{
		Module: "example.com/vulnerable/v2",
		AdditionalPackages: []report.Additional{
			{
				Module:  "vanity.host/vulnerable",
				Package: "vanity.host/vulnerable/package",
				Symbols: []string{"b", "A.b"},
				Versions: []report.VersionRange{
					{Fixed: "v2.1.1"},
					{Introduced: "v2.3.4", Fixed: "v2.3.5"},
					{Introduced: "v2.5.0"},
				},
			},
			{
				Module:  "example.com/also-vulnerable",
				Package: "example.com/also-vulnerable/package",
				Symbols: []string{"z"},
				Versions: []report.VersionRange{
					{Fixed: "v2.1.1"},
				},
			},
		},
		Versions: []report.VersionRange{
			{Fixed: "v2.1.1"},
			{Introduced: "v2.3.4", Fixed: "v2.3.5"},
			{Introduced: "v2.5.0"},
		},
		Description: "It's a real bad one, I'll tell you that",
		CVE:         "CVE-0000-0000",
		Credit:      "ignored",
		Symbols:     []string{"A", "B.b"},
		OS:          []string{"windows"},
		Arch:        []string{"arm64"},
		Links: report.Links{
			PR:      "pr",
			Commit:  "commit",
			Context: []string{"issue-a", "issue-b"},
		},
	}

	url := "https://vulns.golang.org/GO-1991-0001.html"
	wantEntry := Entry{
		ID:      "GO-1991-0001",
		Details: "It's a real bad one, I'll tell you that",
		References: []Reference{
			{Type: "FIX", URL: "pr"},
			{Type: "FIX", URL: "commit"},
			{Type: "WEB", URL: "issue-a"},
			{Type: "WEB", URL: "issue-b"},
		},
		Aliases: []string{"CVE-0000-0000"},
		Affected: []Affected{
			{
				Package: Package{
					Name:      "example.com/vulnerable/v2",
					Ecosystem: "Go",
				},
				Ranges: []AffectsRange{
					{
						Type: TypeSemver,
						Events: []RangeEvent{
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
				DatabaseSpecific: DatabaseSpecific{URL: url},
				EcosystemSpecific: EcosystemSpecific{
					Symbols: []string{"A", "B.b"},
					GOOS:    []string{"windows"},
					GOARCH:  []string{"arm64"},
				},
			},
			{
				Package: Package{
					Name:      "vanity.host/vulnerable/package",
					Ecosystem: "Go",
				},
				Ranges: []AffectsRange{
					{
						Type: TypeSemver,
						Events: []RangeEvent{
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
				DatabaseSpecific: DatabaseSpecific{URL: url},
				EcosystemSpecific: EcosystemSpecific{
					Symbols: []string{"b", "A.b"},
					GOOS:    []string{"windows"},
					GOARCH:  []string{"arm64"},
				},
			},
			{
				Package: Package{
					Name:      "example.com/also-vulnerable/package",
					Ecosystem: "Go",
				},
				Ranges: []AffectsRange{
					{
						Type: TypeSemver,
						Events: []RangeEvent{
							{
								Introduced: "0",
							},
							{
								Fixed: "2.1.1",
							},
						},
					},
				},
				DatabaseSpecific: DatabaseSpecific{URL: url},
				EcosystemSpecific: EcosystemSpecific{
					Symbols: []string{"z"},
					GOOS:    []string{"windows"},
					GOARCH:  []string{"arm64"},
				},
			},
		},
	}
	wantModules := []string{"example.com/vulnerable/v2", "vanity.host/vulnerable", "example.com/also-vulnerable"}
	sort.Strings(wantModules)

	gotEntry, gotModules := Generate("GO-1991-0001", url, r)
	if diff := cmp.Diff(wantEntry, gotEntry, cmp.Comparer(func(a, b time.Time) bool { return a.Equal(b) })); diff != "" {
		t.Errorf("Generate returned unexpected entry (-want +got):\n%s", diff)
	}
	sort.Strings(gotModules)
	if !reflect.DeepEqual(gotModules, wantModules) {
		t.Errorf("Generate returned unexpected modules: got %v, want %v", gotModules, wantModules)
	}
}

func TestAffectsSemver(t *testing.T) {
	cases := []struct {
		affects Affects
		version string
		want    bool
	}{
		{
			// empty Affects indicates everything is affected
			affects: Affects{},
			version: "v0.0.0",
			want:    true,
		},
		{
			// Affects containing an empty SEMVER range also indicates
			// everything is affected
			affects: []AffectsRange{{Type: TypeSemver}},
			version: "v0.0.0",
			want:    true,
		},
		{
			// Affects containing a SEMVER range with only an "introduced":"0"
			// also indicates everything is affected
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "0"}}}},
			version: "v0.0.0",
			want:    true,
		},
		{
			// v1.0.0 < v2.0.0
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "0.0.1"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "1.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0 < v2.0.0
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0 < v2.0.0
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v2.0.0 < v3.0.0
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Multiple ranges
			affects: []AffectsRange{{Type: TypeSemver, Events: []RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}, {Introduced: "3.0.0"}}}},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Wrong type range
			affects: []AffectsRange{{Type: TypeUnspecified, Events: []RangeEvent{{Introduced: "3.0.0"}}}},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges don't match
			affects: []AffectsRange{
				{Type: TypeUnspecified, Events: []RangeEvent{{Introduced: "3.0.0"}}},
				{Type: TypeSemver, Events: []RangeEvent{{Introduced: "4.0.0"}}},
			},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Semver ranges do match
			affects: []AffectsRange{
				{Type: TypeUnspecified, Events: []RangeEvent{{Introduced: "3.0.0"}}},
				{Type: TypeSemver, Events: []RangeEvent{{Introduced: "3.0.0"}}},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges match (go prefix)
			affects: []AffectsRange{
				{Type: TypeSemver, Events: []RangeEvent{{Introduced: "3.0.0"}}},
			},
			version: "go3.0.1",
			want:    true,
		},
	}

	for _, c := range cases {
		got := c.affects.AffectsSemver(c.version)
		if c.want != got {
			t.Errorf("%#v.AffectsSemver(%s): want %t, got %t", c.affects, c.version, c.want, got)
		}
	}
}
