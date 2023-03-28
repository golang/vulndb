// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package legacydb

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/client"
	"golang.org/x/vulndb/internal/osv"
)

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
	t.Run("ok", func(t *testing.T) {
		path := validDir
		got, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%s): want success, got %s", path, err)
		}
		want := valid
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("Load(%s): unexpected diff (want- got+):\n %s", path, diff)
		}
	})

	failTests := []struct {
		name    string
		dbPath  string
		wantErr string
	}{
		{
			name:    "missing file",
			dbPath:  "testdata/db/missing-file",
			wantErr: "invalid or missing",
		},
		{
			name:    "unexpected file",
			dbPath:  "testdata/db/unexpected-file",
			wantErr: "found unexpected file",
		},
	}
	for _, test := range failTests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(test.dbPath)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Load(%s): want err containing %s, got %v", test.dbPath, test.wantErr, err)
			}
		})
	}
}

func TestCheckInternalConsistency(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if err := valid.checkInternalConsistency(); err != nil {
			t.Error(err)
		}
	})

	failTests := []struct {
		name    string
		db      *Database
		wantErr string
	}{
		{
			name: "too many modules",
			db: &Database{
				EntriesByModule: EntriesByModule{"module": []*osv.Entry{}},
			},
			wantErr: "length mismatch",
		},
		{
			name: "missing module from index",
			db: &Database{
				Index:           client.DBIndex{"module": time.Time{}},
				EntriesByModule: EntriesByModule{"module2": []*osv.Entry{}},
			},
			wantErr: "no module directory found",
		},
		{
			name: "missing OSV from module reference",
			db: &Database{
				Index: client.DBIndex{"module": time.Time{}},
				EntriesByModule: EntriesByModule{"module": []*osv.Entry{
					{ID: "GO-1999-0001"},
				}},
				EntriesByID: EntriesByID{},
			},
			wantErr: "no advisory found for ID GO-1999-0001",
		},
		{
			name: "inconsistent OSV",
			db: &Database{
				Index: client.DBIndex{"module": time.Time{}},
				EntriesByModule: EntriesByModule{"module": []*osv.Entry{
					{ID: "GO-1999-0001"},
				}},
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001",
					Published: jan1999}},
			},
			wantErr: "inconsistent OSV contents",
		},
		{
			name: "incorrect modified timestamp in index",
			db: &Database{
				Index: client.DBIndex{"module": jan2000},
				EntriesByModule: EntriesByModule{"module": []*osv.Entry{
					{ID: "GO-1999-0001", Modified: jan1999,
						Affected: []osv.Affected{
							{
								Package: osv.Package{
									Name: "module",
								},
							},
						}},
				}},
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001",
					Modified: jan1999, Affected: []osv.Affected{
						{
							Package: osv.Package{
								Name: "module",
							},
						},
					}}},
			},
			wantErr: "incorrect modified timestamp",
		},
		{
			name: "missing module referenced by OSV",
			db: &Database{
				Index:           client.DBIndex{},
				EntriesByModule: EntriesByModule{},
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001",
					Affected: []osv.Affected{
						{
							Package: osv.Package{
								Name: "a/module",
							},
						},
					},
				}}},
			wantErr: "module a/module not found",
		},
		{
			name: "OSV does not reference module",
			db: &Database{
				Index: client.DBIndex{"module": time.Time{}},
				EntriesByModule: EntriesByModule{"module": []*osv.Entry{
					{ID: "GO-1999-0001"},
				}},
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001"}},
			},
			wantErr: "GO-1999-0001 does not reference module",
		},
		{
			name: "missing OSV entry in module",
			db: &Database{
				Index: client.DBIndex{"module": time.Time{}},
				EntriesByModule: EntriesByModule{"module": []*osv.Entry{
					{ID: "GO-1999-0002",
						Affected: []osv.Affected{
							{
								Package: osv.Package{
									Name: "module",
								},
							},
						},
					}}},
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001",
					Affected: []osv.Affected{
						{
							Package: osv.Package{
								Name: "module",
							},
						},
					},
				}, "GO-1999-0002": {ID: "GO-1999-0002",
					Affected: []osv.Affected{
						{
							Package: osv.Package{
								Name: "module",
							},
						},
					},
				},
				}},
			wantErr: "GO-1999-0001 does not have an entry in module",
		},
		{
			name: "missing alias in aliases.json",
			db: &Database{
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001", Aliases: []string{"CVE-1999-0001"}}},
				IDsByAlias:  IDsByAlias{},
			},
			wantErr: "alias CVE-1999-0001 not found",
		},
		{
			name: "missing OSV reference in aliases.json",
			db: &Database{
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001", Aliases: []string{"CVE-1999-0001"}}},
				IDsByAlias:  IDsByAlias{"CVE-1999-0001": []string{"GO-2000-2222"}},
			},
			wantErr: "GO-1999-0001 is not listed as an alias of CVE-1999-0001",
		},
		{
			name: "missing OSV referenced by aliases.json",
			db: &Database{
				IDsByAlias: IDsByAlias{"CVE-1999-0001": []string{"GO-1999-0001"}},
			},
			wantErr: "no advisory found for GO-1999-0001 listed under CVE-1999-0001",
		},
		{
			name: "missing alias in OSV",
			db: &Database{
				EntriesByID: EntriesByID{"GO-1999-0001": {ID: "GO-1999-0001"}},
				IDsByAlias:  IDsByAlias{"CVE-1999-0001": []string{"GO-1999-0001"}},
			},
			wantErr: "advisory GO-1999-0001 does not reference alias CVE-1999-0001",
		},
	}
	for _, test := range failTests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.db.checkInternalConsistency(); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("want error containing %q, got %v", test.wantErr, err)
			}
		})
	}
}
