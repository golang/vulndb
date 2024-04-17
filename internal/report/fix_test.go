// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
)

func TestFix(t *testing.T) {
	r := Report{
		Modules: []*Module{
			{
				Module: "std",
				Versions: []VersionRange{
					{
						Introduced: "go1.20",
					},
					{
						Fixed: "go1.20.1",
					},
					{
						Introduced: "go1.19",
						Fixed:      "go1.19.5",
					},
					{
						Fixed: "go1.18.5",
					},
				},
				VulnerableAt: "go1.20",
			},
			{
				Module: "golang.org/x/vulndb",
				Versions: []VersionRange{{
					Introduced: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
				}},
				VulnerableAt: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
			},
		},
		Description: "A long form description of the problem that will be broken up into multiple lines so it is more readable.",
		References: []*Reference{
			{
				URL: "https://github.com/golang/go/issues/123",
			},
		},
	}
	want := Report{
		Summary: "Vulnerability in golang.org/x/vulndb",
		Modules: []*Module{
			{
				Module: "golang.org/x/vulndb",
				Versions: []VersionRange{{
					Introduced: "0.0.0-20230522180520-0cbf4ffdb4e7",
				}},
				VulnerableAt: "0.0.0-20230522180520-0cbf4ffdb4e7",
			},
			{
				Module: "std",
				Versions: []VersionRange{
					{
						Fixed: "1.18.5",
					},
					{
						Introduced: "1.19.0",
						Fixed:      "1.19.5",
					},
					{
						Introduced: "1.20.0",
						Fixed:      "1.20.1",
					},
				},
				VulnerableAt: "1.20.0",
			},
		},
		Description: "A long form description of the problem that will be broken up into multiple\nlines so it is more readable.",
		References: []*Reference{
			{
				URL: "https://go.dev/issue/123",
			},
		},
	}

	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	r.Fix(pc)

	got := r
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Fix() mismatch (-want +got):\n%s", diff)
	}
}

func TestFixLineLength(t *testing.T) {
	tcs := []struct {
		name    string
		n       int
		unfixed string
		want    string
	}{
		{
			name:    "empty",
			n:       1,
			unfixed: "",
			want:    "",
		},
		{
			name: "multiple paragraphs with long lines",
			n:    80,
			unfixed: `Incorrect access control is possible in the go command.

The go command can misinterpret branch names that falsely appear to be version tags.
This can lead to incorrect access control if an actor is authorized to create branches
but not tags.`,
			want: `Incorrect access control is possible in the go command.

The go command can misinterpret branch names that falsely appear to be version
tags. This can lead to incorrect access control if an actor is authorized to
create branches but not tags.`,
		},
		{
			name:    "one paragraph",
			n:       15,
			unfixed: "A single paragraph description.",
			want:    "A single\nparagraph\ndescription.",
		},
		{
			name:    "word longer than max",
			n:       10,
			unfixed: "A single verylongword on its own line is OK",
			want:    "A single\nverylongword\non its own\nline is OK",
		},
		{
			name:    "word longer than max with paragraph",
			n:       10,
			unfixed: "A single\n\nverylongword\n\non its own",
			want:    "A single\n\nverylongword\n\non its own",
		},
		{
			name:    "ok - exactly at max",
			n:       19,
			unfixed: "This is already OK.\nThis is already OK.",
			want:    "This is already OK.\nThis is already OK.",
		},
		{
			name:    "ok - shorter than max",
			n:       20,
			unfixed: "This is already OK.",
			want:    "This is already OK.",
		},
		{
			name: "markdown",
			n:    20,
			unfixed: `Hello

1. this is a point
2. this is a longer point that will be broken up
3. this is point 3`,
			want: `Hello

1. this is a point
2. this is a longer
point that will be
broken up
3. this is point 3`,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := fixLineLength(tc.unfixed, tc.n)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("fixLineLength() mismatch (-want +got):\n%s\n%s", diff, got)
			}
		})
	}
}

func TestGuessVulnerableAt(t *testing.T) {
	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		m    *Module
		want string
	}{
		{
			name: "no fix",
			m: &Module{
				Module: "golang.org/x/tools",
			},
			want: "0.12.0", // latest
		},
		{
			name: "has fix",
			m: &Module{
				Module: "golang.org/x/tools",
				Versions: []VersionRange{
					{
						Fixed: "0.1.8",
					},
				},
			},
			want: "0.1.7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.m.guessVulnerableAt(pc)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("guessVulnerableAt() = %q, want %s", got, tc.want)
			}
		})
	}
}

// To update proxy responses:
// go test ./internal/report/... -proxy -run TestFixModules
func TestFixModules(t *testing.T) {
	for _, tc := range []struct {
		name string
		desc string
		in   []*Module
		want []*Module
	}{
		{
			name: "ok",
			desc: "module is already OK",
			in: []*Module{{
				Module: "github.com/influxdata/influxdb",
				Versions: []VersionRange{
					{
						Introduced: "0.3.2",
						Fixed:      "1.7.6",
					}},
				VulnerableAt: "1.7.5",
			}},
			want: []*Module{{
				Module: "github.com/influxdata/influxdb",
				Versions: []VersionRange{
					{
						Introduced: "0.3.2",
						Fixed:      "1.7.6",
					}},
				VulnerableAt: "1.7.5",
			}},
		},
		{
			name: "import_path",
			desc: "find module from import path",
			in: []*Module{{
				Module: "github.com/influxdata/influxdb/services/httpd",
				Versions: []VersionRange{
					{
						Introduced: "0.3.2",
						Fixed:      "1.7.6",
					},
				},
			}},
			want: []*Module{{
				Module: "github.com/influxdata/influxdb",
				Versions: []VersionRange{
					{
						Introduced: "0.3.2",
						Fixed:      "1.7.6",
					},
				},
				Packages: []*Package{
					{
						Package: "github.com/influxdata/influxdb/services/httpd",
					},
				},
				VulnerableAt: "1.7.5",
			}},
		},
		{
			name: "major_version",
			desc: "correct major version of module path",
			in: []*Module{{
				Module: "github.com/nats-io/nats-server",
				Versions: []VersionRange{
					{
						Introduced: "2.2.0",
						Fixed:      "2.8.3",
					},
				},
			}},
			want: []*Module{{
				Module: "github.com/nats-io/nats-server/v2",
				Versions: []VersionRange{
					{
						Introduced: "2.2.0",
						Fixed:      "2.8.3",
					},
				},
				VulnerableAt: "2.8.2",
			}},
		},
		{
			name: "canonicalize",
			desc: "canonicalize module path",
			in: []*Module{{
				Module: "github.com/golang/vulndb",
				Versions: []VersionRange{
					{
						Fixed: "0.0.0-20230712151357-4fee11d0f8f9",
					},
				},
			}},
			want: []*Module{{
				Module: "golang.org/x/vulndb",
				Versions: []VersionRange{
					{
						Fixed: "0.0.0-20230712151357-4fee11d0f8f9",
					},
				},
			}},
		},
		{
			name: "add_incompatible",
			desc: "add +incompatible",
			in: []*Module{{
				Module: "github.com/docker/docker",
				Versions: []VersionRange{
					{
						Fixed: "23.0.0",
					},
				},
			}},
			want: []*Module{{
				Module: "github.com/docker/docker",
				Versions: []VersionRange{
					{
						Fixed: "23.0.0+incompatible",
					},
				},
				VulnerableAt: "23.0.0-rc.4+incompatible",
			}},
		},
		{
			name: "merge_modules",
			desc: "merge modules that are the same except for versions",
			in: []*Module{{
				Module: "github.com/hashicorp/go-getter/v2",
				Versions: []VersionRange{
					{
						Introduced: "2.0.0",
						Fixed:      "2.0.2",
					},
				},
			},
				{
					Module: "github.com/hashicorp/go-getter/v2",
					Versions: []VersionRange{
						{
							Introduced: "2.1.0",
							Fixed:      "2.1.1",
						},
					},
				},
			},
			want: []*Module{{
				Module: "github.com/hashicorp/go-getter/v2",
				Versions: []VersionRange{
					{
						Introduced: "2.0.0",
						Fixed:      "2.0.2",
					},
					{
						Introduced: "2.1.0",
						Fixed:      "2.1.1",
					},
				},
				VulnerableAt: "2.1.0",
			}},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pc, err := proxy.NewTestClient(t, *realProxy)
			if err != nil {
				t.Fatal(err)
			}

			r := &Report{Modules: tc.in}
			r.FixModules(pc)
			got := r.Modules

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("%s: FixModules() mismatch (-want +got)\n%s", tc.desc, diff)
			}
		})
	}
}

func TestFixReferences(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in, want []*Reference
	}{
		{
			// GHSA references are converted to advisory type
			name: "to_advisory_ghsa",
			in: []*Reference{
				{
					URL:  "https://github.com/example/module/security/advisories/GHSA-xxxx-yyyy-zzzz",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/other/module/security/advisories/GHSA-xxxx-yyyy-zzzz",
					Type: osv.ReferenceTypeWeb,
				},
			},
			want: []*Reference{
				{
					URL:  "https://github.com/example/module/security/advisories/GHSA-xxxx-yyyy-zzzz",
					Type: osv.ReferenceTypeAdvisory,
				},
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeAdvisory,
				},
				{
					URL:  "https://github.com/other/module/security/advisories/GHSA-xxxx-yyyy-zzzz",
					Type: osv.ReferenceTypeAdvisory, // different module OK, because GHSA matches
				},
			},
		},
		{
			// CVE references are converted to advisory type
			name: "to_advisory_cve",
			in: []*Reference{
				{
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-1999-0001",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-1999-2222",
					Type: osv.ReferenceTypeWeb,
				},
			},
			want: []*Reference{
				{
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-1999-0001",
					Type: osv.ReferenceTypeAdvisory,
				},
				{
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-1999-2222",
					Type: osv.ReferenceTypeWeb, // different CVE, keep "web" type
				},
			},
		},
		{
			// CVE references are removed if GHSA is present
			name: "remove_cve",
			in: []*Reference{
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-1999-0001",
					Type: osv.ReferenceTypeWeb,
				},
			},
			want: []*Reference{
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeAdvisory,
				},
			},
		},
		{
			name: "to_fix_or_report",
			in: []*Reference{
				{
					URL:  "https://github.com/example/module/pull/123",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/example/module/commit/123",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/module/module/issues/123",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/example/module/issue/123",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/different/module/issue/123",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeAdvisory,
				},
			},
			want: []*Reference{
				{
					URL:  "https://github.com/example/module/pull/123",
					Type: osv.ReferenceTypeFix,
				},
				{
					URL:  "https://github.com/example/module/commit/123",
					Type: osv.ReferenceTypeFix,
				},
				{
					URL:  "https://github.com/module/module/issues/123",
					Type: osv.ReferenceTypeReport,
				},
				{
					URL:  "https://github.com/example/module/issue/123",
					Type: osv.ReferenceTypeReport,
				},
				{
					URL:  "https://github.com/different/module/issue/123",
					Type: osv.ReferenceTypeWeb, // different module, keep web type
				},
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeAdvisory,
				},
			},
		},
		{
			// package references and go advisory references are deleted
			name: "delete",
			in: []*Reference{
				{
					URL:  "https://pkg.go.dev/vuln/GO-0000-0000",
					Type: osv.ReferenceTypeWeb,
				},
				{
					URL:  "https://github.com/anything",
					Type: osv.ReferenceTypePackage,
				},
				{
					URL:  "https://example.com",
					Type: osv.ReferenceTypePackage,
				},
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeAdvisory,
				},
			},
			want: []*Reference{
				{
					URL:  "https://github.com/advisories/GHSA-gggg-hhhh-ffff",
					Type: osv.ReferenceTypeAdvisory,
				},
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &Report{
				Modules: []*Module{
					{
						Module: "github.com/example/module",
					},
					{
						Module: "github.com/module/module",
					},
				},
				GHSAs:      []string{"GHSA-xxxx-yyyy-zzzz", "GHSA-gggg-hhhh-ffff"},
				CVEs:       []string{"CVE-1999-0001", "CVE-1999-0002"},
				References: tc.in,
			}
			r.FixReferences()
			got := r.References
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("FixReferences() mismatch (-want +got)\n%s", diff)
			}
		})
	}
}
