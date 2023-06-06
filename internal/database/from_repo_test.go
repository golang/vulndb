// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

var (
	testOSV4 = osv.Entry{
		SchemaVersion: report.SchemaVersion,
		ID:            "GO-1999-0001",
		Published:     jan2002, // overwritten because unset
		Modified:      jan2002, // overwritten
		Aliases:       []string{"CVE-1999-1111"},
		Summary:       "A summary",
		Details:       "Some details",
		Affected: []osv.Affected{
			{
				Module: osv.Module{
					Path:      "stdlib",
					Ecosystem: "Go",
				},
				Ranges: []osv.Range{
					{
						Type: "SEMVER",
						Events: []osv.RangeEvent{
							{Introduced: "0"}, {Fixed: "1.1.0"},
							{Introduced: "1.2.0"},
							{Fixed: "1.2.2"},
						}}},
				EcosystemSpecific: &osv.EcosystemSpecific{
					Packages: []osv.Package{{Path: "package", Symbols: []string{"Symbol"}}}}},
		},
		References: []osv.Reference{
			{Type: "FIX", URL: "https://example.com/cl/123"},
		},
		DatabaseSpecific: &osv.DatabaseSpecific{
			URL: "https://pkg.go.dev/vuln/GO-1999-0001"},
	}
	testOSV5 = osv.Entry{
		SchemaVersion: report.SchemaVersion,
		ID:            "GO-2000-0002",
		Published:     jan2000, // not overwritten
		Modified:      jan2002, // overwritten
		Aliases:       []string{"CVE-1999-2222"},
		Summary:       "A summary",
		Details:       "Some details",
		Affected: []osv.Affected{
			{
				Module: osv.Module{
					Path:      "example.com/module",
					Ecosystem: "Go",
				},
				Ranges: []osv.Range{
					{
						Type: "SEMVER", Events: []osv.RangeEvent{{Introduced: "0"},
							{Fixed: "1.2.0"},
						}}},
				EcosystemSpecific: &osv.EcosystemSpecific{
					Packages: []osv.Package{{Path: "example.com/module/package",
						Symbols: []string{"Symbol"},
					}}}}},
		References: []osv.Reference{
			{Type: "FIX", URL: "https://example.com/cl/543"},
		},
		DatabaseSpecific: &osv.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/GO-2000-0002"}}
	testOSV6 = osv.Entry{
		SchemaVersion: report.SchemaVersion,
		ID:            "GO-2000-0003",
		Published:     jan2000, // not overwritten
		Modified:      jan2002, // overwritten
		Aliases:       []string{"CVE-1999-3333", "GHSA-xxxx-yyyy-zzzz"},
		Summary:       "A summary",
		Details:       "Some details",
		Affected: []osv.Affected{
			{
				Module: osv.Module{
					Path:      "example.com/module",
					Ecosystem: "Go",
				},
				Ranges: []osv.Range{
					{
						Type: "SEMVER",
						Events: []osv.RangeEvent{
							{Introduced: "0"}, {Fixed: "1.1.0"},
						}}},
				EcosystemSpecific: &osv.EcosystemSpecific{Packages: []osv.Package{
					{
						Path:    "example.com/module/package",
						Symbols: []string{"Symbol"},
					}}}}},
		References: []osv.Reference{
			{Type: "FIX", URL: "https://example.com/cl/000"},
		},
		DatabaseSpecific: &osv.DatabaseSpecific{
			URL: "https://pkg.go.dev/vuln/GO-2000-0003",
		},
	}
	validFromRepo = &Database{
		DB:      DBMeta{Modified: jan2002},
		Modules: ModulesIndex{"example.com/module": &Module{Path: "example.com/module", Vulns: []ModuleVuln{{ID: "GO-2000-0002", Modified: jan2002, Fixed: "1.2.0"}, {ID: "GO-2000-0003", Modified: jan2002, Fixed: "1.1.0"}}}, "stdlib": &Module{Path: "stdlib", Vulns: []ModuleVuln{{ID: "GO-1999-0001", Modified: jan2002, Fixed: "1.2.2"}}}},
		Vulns:   VulnsIndex{"GO-1999-0001": &Vuln{ID: "GO-1999-0001", Modified: jan2002, Aliases: []string{"CVE-1999-1111"}}, "GO-2000-0002": &Vuln{ID: "GO-2000-0002", Modified: jan2002, Aliases: []string{"CVE-1999-2222"}}, "GO-2000-0003": &Vuln{ID: "GO-2000-0003", Modified: jan2002, Aliases: []string{"CVE-1999-3333", "GHSA-xxxx-yyyy-zzzz"}}},
		Entries: []osv.Entry{testOSV4, testOSV5, testOSV6}}
)

func TestFromRepo(t *testing.T) {
	// Checks that modified and published times are set correctly
	// when we read from a repo.
	ctx := context.Background()
	testRepo, err := gitrepo.ReadTxtarRepo(vulndbTxtar, jan2002.Time)
	if err != nil {
		t.Fatal(err)
	}

	got, err := FromRepo(ctx, testRepo)
	if err != nil {
		t.Fatal(err)
	}

	want := validFromRepo
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("FromRepo: unexpected diff (-want, +got):\n%s", diff)
	}
}
