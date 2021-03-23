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
		AdditionalPackages: []struct {
			Module   string
			Package  string
			Symbols  []string
			Versions []report.VersionRange
		}{
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
		Severity:    "medium",
		CVE:         "CVE-0000-0000",
		Credit:      "ignored",
		Symbols:     []string{"A", "B.b"},
		OS:          []string{"windows"},
		Arch:        []string{"arm64"},
		Links: struct {
			PR      string
			Commit  string
			Context []string
		}{
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
				Ecosystem: "go",
			},
			Details:  "It's a real bad one, I'll tell you that",
			Severity: 2,
			Affects: Affects{
				Ranges: []AffectsRange{
					{
						Type:  TypeSemver,
						Fixed: "v2.1.1",
					},
					{
						Type:       TypeSemver,
						Introduced: "v2.3.4",
						Fixed:      "v2.3.5",
					},
					{
						Type:       TypeSemver,
						Introduced: "v2.5.0",
					},
				},
			},
			ReferenceURLs: []string{
				"pr",
				"commit",
				"issue-a",
				"issue-b",
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
				Ecosystem: "go",
			},
			Details:  "It's a real bad one, I'll tell you that",
			Severity: 2,
			Affects: Affects{
				Ranges: []AffectsRange{
					{
						Type:  TypeSemver,
						Fixed: "v2.1.1",
					},
					{
						Type:       TypeSemver,
						Introduced: "v2.3.4",
						Fixed:      "v2.3.5",
					},
					{
						Type:       TypeSemver,
						Introduced: "v2.5.0",
					},
				},
			},
			ReferenceURLs: []string{
				"pr",
				"commit",
				"issue-a",
				"issue-b",
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
					{Type: TypeSemver, Fixed: "v2.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "v0.0.1"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "v1.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0 < v2.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "v1.0.0", Fixed: "v2.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0 < v2.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "v0.0.1", Fixed: "v2.0.0"},
				},
			},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v2.0.0 < v3.0.0
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "v1.0.0", Fixed: "v2.0.0"},
				},
			},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Multiple ranges
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeSemver, Introduced: "v1.0.0", Fixed: "v2.0.0"},
					{Type: TypeSemver, Introduced: "v3.0.0"},
				},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Wrong type range
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeUnspecified, Introduced: "v3.0.0"},
				},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges don't match
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeUnspecified, Introduced: "v3.0.0"},
					{Type: TypeSemver, Introduced: "v4.0.0"},
				},
			},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Semver ranges do match
			affects: Affects{
				Ranges: []AffectsRange{
					{Type: TypeUnspecified, Introduced: "v3.0.0"},
					{Type: TypeSemver, Introduced: "v3.0.0"},
				},
			},
			version: "v3.0.0",
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
