// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

// TODO(https://github.com/golang/go#56417): Write unit tests for various
// invalid databases.

var (
	validDir = "testdata/db/valid"
	jan1999  = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	jan2000  = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	jan2002  = time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
	testOSV1 = &osv.Entry{
		ID:        "GO-1999-0001",
		Published: jan1999,
		Modified:  jan2002,
		Aliases:   []string{"CVE-1999-1111"},
		Details:   "Some details",
		Affected: []osv.Affected{
			{
				Package: osv.Package{
					Name:      "example.com/module",
					Ecosystem: "Go",
				},
				Ranges: osv.Affects{
					osv.AffectsRange{
						Type: "SEMVER",
						Events: []osv.RangeEvent{
							{Introduced: "0"}, {Fixed: "1.1.0"},
							{Introduced: "1.2.0"},
							{Fixed: "1.2.2"},
						}}},
				DatabaseSpecific: osv.DatabaseSpecific{
					URL: "https://pkg.go.dev/vuln/GO-1999-0001"},
				EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{Path: "package", Symbols: []string{"Symbol"}}}}},
		},
		References: []osv.Reference{
			{Type: "FIX", URL: "https://example.com/cl/123"},
		}}
	testOSV2 = &osv.Entry{
		ID:        "GO-2000-0002",
		Published: jan2000,
		Modified:  jan2002,
		Aliases:   []string{"CVE-1999-2222"},
		Details:   "Some details",
		Affected: []osv.Affected{
			{
				Package: osv.Package{
					Name:      "example.com/module2",
					Ecosystem: "Go",
				},
				Ranges: osv.Affects{
					osv.AffectsRange{
						Type: "SEMVER", Events: []osv.RangeEvent{{Introduced: "0"},
							{Fixed: "1.2.0"},
						}}},
				DatabaseSpecific: osv.DatabaseSpecific{URL: "https://pkg.go.dev/vuln/GO-2000-0002"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{Path: "package",
						Symbols: []string{"Symbol"},
					}}}}},
		References: []osv.Reference{
			{Type: "FIX", URL: "https://example.com/cl/543"},
		}}
	testOSV3 = &osv.Entry{
		ID:        "GO-2000-0003",
		Published: jan2002,
		Modified:  jan2002,
		Aliases:   []string{"CVE-1999-3333", "GHSA-xxxx-yyyy-zzzz"},
		Details:   "Some details",
		Affected: []osv.Affected{
			{
				Package: osv.Package{
					Name:      "example.com/module2",
					Ecosystem: "Go",
				},
				Ranges: osv.Affects{
					osv.AffectsRange{
						Type: "SEMVER",
						Events: []osv.RangeEvent{
							{Introduced: "0"}, {Fixed: "1.1.0"},
						}}},
				DatabaseSpecific: osv.DatabaseSpecific{
					URL: "https://pkg.go.dev/vuln/GO-2000-0003",
				},
				EcosystemSpecific: osv.EcosystemSpecific{Imports: []osv.EcosystemSpecificImport{
					{
						Path:    "package",
						Symbols: []string{"Symbol"},
					}}}}},
		References: []osv.Reference{
			{Type: "FIX", URL: "https://example.com/cl/000"},
		}}
)

var valid = &Database{
	Index: client.DBIndex{
		"example.com/module":  jan2002,
		"example.com/module2": jan2002,
	},
	EntriesByID: EntriesByID{"GO-1999-0001": testOSV1, "GO-2000-0002": testOSV2, "GO-2000-0003": testOSV3},
	EntriesByModule: EntriesByModule{
		"example.com/module":  {testOSV1},
		"example.com/module2": {testOSV2, testOSV3},
	},
	IDsByAlias: IDsByAlias{
		"CVE-1999-1111":       {"GO-1999-0001"},
		"CVE-1999-2222":       {"GO-2000-0002"},
		"CVE-1999-3333":       {"GO-2000-0003"},
		"GHSA-xxxx-yyyy-zzzz": {"GO-2000-0003"},
	},
}

func TestLoad(t *testing.T) {
	path := validDir
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%s): want succeess, got %s", path, err)
	}
	want := valid
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load(%s): unexpected diff (want- got+):\n %s", path, diff)
	}
}
