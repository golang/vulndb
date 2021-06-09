// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osv

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/report"
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

	want := []Entry{
		{
			ID: "GO-1991-0001",
			Package: Package{
				Name:      "example.com/vulnerable/v2",
				Ecosystem: "Go",
			},
			Details: "It's a real bad one, I'll tell you that",
			Affects: Affects{
				Ranges: []AffectsRange{
					{
						Type:  TypeSemver,
						Fixed: "2.1.1",
					},
					{
						Type:       TypeSemver,
						Introduced: "2.3.4",
						Fixed:      "2.3.5",
					},
					{
						Type:       TypeSemver,
						Introduced: "2.5.0",
					},
				},
			},
			References: []Reference{
				Reference{Type: "FIX", URL: "pr"},
				Reference{Type: "FIX", URL: "commit"},
				Reference{Type: "WEB", URL: "issue-a"},
				Reference{Type: "WEB", URL: "issue-b"},
			},
			Aliases: []string{"CVE-0000-0000"},
			EcosystemSpecific: GoSpecific{
				Symbols: []string{"A", "B.b"},
				GOOS:    []string{"windows"},
				GOARCH:  []string{"arm64"},
				URL:     "https://vulns.golang.org/GO-1991-0001.html",
			},
		},
		{

			ID: "GO-1991-0001",
			Package: Package{
				Name:      "vanity.host/vulnerable/package",
				Ecosystem: "Go",
			},
			Details: "It's a real bad one, I'll tell you that",
			Affects: Affects{
				Ranges: []AffectsRange{
					{
						Type:  TypeSemver,
						Fixed: "2.1.1",
					},
					{
						Type:       TypeSemver,
						Introduced: "2.3.4",
						Fixed:      "2.3.5",
					},
					{
						Type:       TypeSemver,
						Introduced: "2.5.0",
					},
				},
			},
			References: []Reference{
				Reference{Type: "FIX", URL: "pr"},
				Reference{Type: "FIX", URL: "commit"},
				Reference{Type: "WEB", URL: "issue-a"},
				Reference{Type: "WEB", URL: "issue-b"},
			},
			Aliases: []string{"CVE-0000-0000"},
			EcosystemSpecific: GoSpecific{
				Symbols: []string{"b", "A.b"},
				GOOS:    []string{"windows"},
				GOARCH:  []string{"arm64"},
				URL:     "https://vulns.golang.org/GO-1991-0001.html",
			},
		},
	}
	got := Generate("GO-1991-0001", "https://vulns.golang.org/GO-1991-0001.html", r)
	if diff := cmp.Diff(want, got, cmp.Comparer(func(_, _ time.Time) bool { return true })); diff != "" {
		t.Errorf("Generate returned unexpected result (-want +got):\n%s", diff)
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
			// v1.0.0 < v2.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Fixed: "2.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "0.0.1"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "1.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0 < v2.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "1.0.0", Fixed: "2.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0 < v2.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "0.0.1", Fixed: "2.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v2.0.0 < v3.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "1.0.0", Fixed: "2.0.0"},
				},
			},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Multiple ranges
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "1.0.0", Fixed: "2.0.0"},
					{Type: TypeSemver, Introduced: "3.0.0"},
				},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Wrong type range
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeUnspecified, Introduced: "3.0.0"},
				},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges don't match
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeUnspecified, Introduced: "3.0.0"},
					{Type: TypeSemver, Introduced: "4.0.0"},
				},
			},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Semver ranges do match
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeUnspecified, Introduced: "3.0.0"},
					{Type: TypeSemver, Introduced: "3.0.0"},
				},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges match (go prefix)
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "3.0.0"},
				},
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
