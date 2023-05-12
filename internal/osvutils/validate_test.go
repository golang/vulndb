// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osvutils

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/vulndb/internal/osv"
)

var (
	jan1999 = osv.Time{Time: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)}
	jan2000 = osv.Time{Time: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
)

// testEntry creates a valid Entry and modifies it by running transform.
// If transform is nil, it returns the base test Entry.
func testEntry(transform func(e *osv.Entry)) *osv.Entry {
	e := &osv.Entry{
		SchemaVersion: "1.3.1",
		ID:            "GO-1999-0001",
		Published:     jan1999,
		Modified:      jan2000,
		Aliases:       []string{"CVE-1999-1111"},
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
							{Introduced: "1.2.0"},
							{Fixed: "1.2.2"},
						}}},
				EcosystemSpecific: &osv.EcosystemSpecific{
					Packages: []osv.Package{{Path: "example.com/module/package", Symbols: []string{"Symbol"}}}}},
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
			URL: "https://pkg.go.dev/vuln/GO-1999-0001"}}

	if transform == nil {
		return e
	}

	transform(e)
	return e
}

func TestValidate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if err := Validate(testEntry(nil)); err != nil {
			t.Error(err)
		}
		if err := ValidateExceptTimestamps(testEntry(nil)); err != nil {
			t.Error("ValidateExceptTimestamps():", err)
		}
	})

	t.Run("timestamps", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			entry   *osv.Entry
			wantErr error
		}{
			{
				name: "no modified",
				entry: testEntry(func(e *osv.Entry) {
					e.Modified = osv.Time{}
				}),
				wantErr: errNoModified,
			},
			{
				name: "no published",
				entry: testEntry(func(e *osv.Entry) {
					e.Published = osv.Time{}
				}),
				wantErr: errNoPublished,
			},
			{
				name: "published after modified",
				entry: testEntry(func(e *osv.Entry) {
					e.Modified = jan1999
					e.Published = jan2000
				}),
				wantErr: errPublishedAfterModified,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				want := tc.wantErr
				if got := Validate(tc.entry); !errors.Is(got, want) {
					t.Errorf("Validate() error = %v, want error %v", got, want)
				}

				// There should be no error when we don't check timestamps.
				if err := ValidateExceptTimestamps(tc.entry); err != nil {
					t.Errorf("ValidateExceptTimestamps() error = %v", err)
				}
			})
		}

	})

	t.Run("fail", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			entry   *osv.Entry
			wantErr error
		}{
			{
				name: "no ID",
				entry: testEntry(func(e *osv.Entry) {
					e.ID = ""
				}),
				wantErr: errNoID,
			},
			{
				name: "no schema version",
				entry: testEntry(func(e *osv.Entry) {
					e.SchemaVersion = ""
				}),
				wantErr: errNoSchemaVersion,
			},
			{
				name: "no details",
				entry: testEntry(func(e *osv.Entry) {
					e.Details = ""
				}),
				wantErr: errNoDetails,
			},
			{
				name: "no affected",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected = nil
				}),
				wantErr: errNoAffected,
			},
			{
				name: "no references",
				entry: testEntry(func(e *osv.Entry) {
					e.References = nil
				}),
				wantErr: errNoReferences,
			},
			{
				name: "no database specific",
				entry: testEntry(func(e *osv.Entry) {
					e.DatabaseSpecific = nil
				}),
				wantErr: errNoDatabaseSpecific,
			},
			{
				name: "missing module path",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Module.Path = ""
				}),
				wantErr: errNoModule,
			},
			{
				name: "non-Go ecosystem",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Module.Ecosystem = "Goo"
				}),
				wantErr: errNotGoEcosystem,
			},
			{
				name: "no version ranges",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges = nil
				}),
				wantErr: errNoRanges,
			},
			{
				name: "no ecosystem specific",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].EcosystemSpecific = nil
				}),
				wantErr: errNoEcosystemSpecific,
			},
			{
				name: "no packages",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].EcosystemSpecific.Packages = nil
				}),
				wantErr: errNoPackages,
			},
			{
				name: "no package path",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].EcosystemSpecific.Packages[0].Path = ""
				}),
				wantErr: errNoPackagePath,
			},
			{
				name: "invalid alias",
				entry: testEntry(func(e *osv.Entry) {
					e.Aliases = append(e.Aliases, "CVE-GHSA-123")
				}),
				wantErr: errInvalidAlias,
			},
			{
				name: "invalid pkgsite URL",
				entry: testEntry(func(e *osv.Entry) {
					// missing "/vuln/"
					e.DatabaseSpecific.URL = "https://pkg.go.dev/GO-1234-5667"
				}),
				wantErr: errInvalidPkgsiteURL,
			},
			{
				name: "package path not prefixed by module path",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Module.Path = "example.com/module"
					e.Affected[0].EcosystemSpecific.Packages[0].Path = "example.com/package"
				}),
				wantErr: errInvalidPackagePath,
			},
			{
				name: "more than one version range",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges = append(e.Affected[0].Ranges, osv.Range{})
				}),
				wantErr: errTooManyRanges,
			},
			{
				name: "non-SEMVER range",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Type = "unknown"
				}),
				wantErr: errRangeTypeNotSemver,
			},
			{
				name: "no range events",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Events = nil
				}),
				wantErr: errNoRangeEvents,
			},
			{
				name: "out of order range",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Events = []osv.RangeEvent{
						{Fixed: "1.1.1"}, {Fixed: "1.1.2"},
					}
				}),
				wantErr: errOutOfOrderRange,
			},
			{
				name: "unsorted range",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Events = []osv.RangeEvent{
						{Fixed: "1.1.1"}, {Introduced: "1.1.0"},
					}
				}),
				wantErr: errUnsortedRange,
			},
			{
				name: "no introduced or fixed in range event",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Events[0] = osv.RangeEvent{}
				}),
				wantErr: errNoIntroducedOrFixed,
			},
			{
				name: "both introduced and fixed in range event",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Events = []osv.RangeEvent{
						{Introduced: "1.1.0", Fixed: "1.1.1"},
					}
				}),
				wantErr: errBothIntroducedAndFixed,
			},
			{
				name: "non-canonical semver",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Events = []osv.RangeEvent{
						{Introduced: "1.1"},
					}
				}),
				wantErr: errInvalidSemver,
			},
			{
				name: "invalid semver",
				entry: testEntry(func(e *osv.Entry) {
					e.Affected[0].Ranges[0].Events = []osv.RangeEvent{
						{Introduced: "1x2x3"},
					}
				}),
				wantErr: errInvalidSemver,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				want := tc.wantErr
				if got := Validate(tc.entry); !errors.Is(got, want) {
					t.Errorf("Validate() error = %v, want error %v", got, want)
				}
				if got := ValidateExceptTimestamps(tc.entry); !errors.Is(got, want) {
					t.Errorf("ValidateExceptTimestamps() error = %v, want error %v", got, want)
				}
			})
		}
	})
}
