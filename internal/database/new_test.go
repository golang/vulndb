// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

var (
	jan1999  = osv.Time{Time: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)}
	jan2000  = osv.Time{Time: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
	jan2002  = osv.Time{Time: time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)}
	jan2003  = osv.Time{Time: time.Date(2003, 1, 1, 0, 0, 0, 0, time.UTC)}
	testOSV1 = osv.Entry{
		SchemaVersion: report.SchemaVersion,
		ID:            "GO-1999-0001",
		Published:     jan1999,
		Modified:      jan2000,
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
					Packages: []osv.Package{{Path: "package", Symbols: []string{"Symbol"}}}},
			},
		},
		References: []osv.Reference{
			{Type: "FIX", URL: "https://example.com/cl/123"},
		}, DatabaseSpecific: &osv.DatabaseSpecific{
			URL: "https://pkg.go.dev/vuln/GO-1999-0001"}}
	testOSV2 = osv.Entry{
		SchemaVersion: report.SchemaVersion,
		ID:            "GO-2000-0002",
		Published:     jan2000,
		Modified:      jan2002,
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
		}, DatabaseSpecific: &osv.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/GO-2000-0002"}}
	testOSV3 = osv.Entry{
		SchemaVersion: report.SchemaVersion,
		ID:            "GO-2000-0003",
		Published:     jan2000,
		Modified:      jan2003,
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
		}}
	valid = &Database{
		DB: DBMeta{Modified: jan2003},
		Modules: ModulesIndex{
			"example.com/module": &Module{Path: "example.com/module", Vulns: []ModuleVuln{{ID: "GO-2000-0002", Modified: jan2002, Fixed: "1.2.0"}, {ID: "GO-2000-0003", Modified: jan2003, Fixed: "1.1.0"}}}, "stdlib": &Module{Path: "stdlib", Vulns: []ModuleVuln{{ID: "GO-1999-0001", Modified: jan2000, Fixed: "1.2.2"}}},
		},
		Vulns: VulnsIndex{
			"GO-1999-0001": &Vuln{ID: "GO-1999-0001", Modified: jan2000, Aliases: []string{"CVE-1999-1111"}}, "GO-2000-0002": &Vuln{ID: "GO-2000-0002", Modified: jan2002, Aliases: []string{"CVE-1999-2222"}}, "GO-2000-0003": &Vuln{ID: "GO-2000-0003", Modified: jan2003, Aliases: []string{"CVE-1999-3333", "GHSA-xxxx-yyyy-zzzz"}},
		},
		Entries: []osv.Entry{testOSV1, testOSV2, testOSV3}}
)

func TestNew(t *testing.T) {
	got, err := New(testOSV1, testOSV2, testOSV3)
	if err != nil {
		t.Fatal(err)
	}
	want := valid
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("New: unexpected diff (-want, +got):\n%v", diff)
	}
}
