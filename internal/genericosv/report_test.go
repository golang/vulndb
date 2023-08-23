// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genericosv

import (
	"flag"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	osvschema "github.com/google/osv-scanner/pkg/models"
	"golang.org/x/vulndb/internal/report"
)

var update = flag.Bool("update", false, "if true, update test cases")

var (
	testdataDir = "testdata"
	testOSVDir  = filepath.Join(testdataDir, "osv")
	testYAMLDir = filepath.Join(testdataDir, "yaml")
)

// To update test cases to reflect new expected behavior:
// go test ./internal/genericosv/... -update -run TestToReport
//
// TODO(https://go.dev/issues/61769): mock out proxy calls in the non-update
// case so that this test is hermetic.
func TestToReport(t *testing.T) {
	t.Skip("need to mock out proxy calls")
	if err := filepath.WalkDir(testOSVDir, func(path string, f fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if f.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		ghsaID := strings.TrimSuffix(f.Name(), ".json")
		t.Run(ghsaID, func(t *testing.T) {
			t.Parallel()
			osv := Entry{}
			if err := report.UnmarshalFromFile(path, &osv); err != nil {
				t.Fatal(err)
			}
			got := osv.ToReport("GO-TEST-ID")
			yamlFile := filepath.Join(testYAMLDir, ghsaID+".yaml")
			if *update {
				if err := got.Write(yamlFile); err != nil {
					t.Fatal(err)
				}
			}
			want, err := report.Read(yamlFile)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("ToReport() mismatch (-want +got)\n%s", diff)
			}
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TODO(https://go.dev/issues/61769): unskip test cases as we add features.
func TestAffectedToModules(t *testing.T) {
	for _, tc := range []struct {
		desc string
		in   []osvschema.Affected
		want []*report.Module
		skip bool
	}{
		{
			desc: "find module from package",
			in: []osvschema.Affected{{
				Package: osvschema.Package{
					Ecosystem: osvschema.EcosystemGo,
					Name:      "github.com/influxdata/influxdb/services/httpd",
				},
				Ranges: []osvschema.Range{{
					Type: osvschema.RangeEcosystem,
					Events: []osvschema.Event{
						{
							Introduced: "0.3.2",
						},
						{
							Fixed: "1.7.6",
						},
					},
				}},
			}},
			want: []*report.Module{{
				Module: "github.com/influxdata/influxdb",
				Versions: []report.VersionRange{
					{
						Introduced: "0.3.2",
						Fixed:      "1.7.6",
					},
				},
				Packages: []*report.Package{
					{
						Package: "github.com/influxdata/influxdb/services/httpd",
					},
				},
			}},
			skip: true,
		},
		{
			desc: "correct major version of module path",
			in: []osvschema.Affected{{
				Package: osvschema.Package{
					Ecosystem: osvschema.EcosystemGo,
					Name:      "github.com/nats-io/nats-server",
				},
				Ranges: []osvschema.Range{{
					Type: osvschema.RangeEcosystem,
					Events: []osvschema.Event{
						{
							Introduced: "2.2.0",
						},
						{
							Fixed: "2.8.3",
						},
					},
				}},
			}},
			want: []*report.Module{{
				Module: "github.com/nats-io/nats-server/v2",
				Versions: []report.VersionRange{
					{
						Introduced: "2.2.0",
						Fixed:      "2.8.3",
					},
				},
			}},
			skip: true,
		},
		{
			desc: "canonicalize module path",
			in: []osvschema.Affected{{
				Package: osvschema.Package{
					Ecosystem: osvschema.EcosystemGo,
					Name:      "github.com/golang/vulndb",
				},
				Ranges: []osvschema.Range{{
					Type: osvschema.RangeEcosystem,
					Events: []osvschema.Event{
						{
							Fixed: "0.0.0-20230712151357-4fee11d0f8f9",
						},
					},
				}},
			}},
			want: []*report.Module{{
				Module: "golang.org/x/vulndb",
				Versions: []report.VersionRange{
					{
						Fixed: "0.0.0-20230712151357-4fee11d0f8f9",
					},
				},
			}},
			skip: true,
		},
		{
			desc: "add +incompatible",
			in: []osvschema.Affected{{
				Package: osvschema.Package{
					Ecosystem: osvschema.EcosystemGo,
					Name:      "github.com/docker/docker",
				},
				Ranges: []osvschema.Range{{
					Type: osvschema.RangeEcosystem,
					Events: []osvschema.Event{
						{
							Fixed: "23.0.0",
						},
					},
				}},
			}},
			want: []*report.Module{{
				Module: "github.com/docker/docker",
				Versions: []report.VersionRange{
					{
						Fixed: "23.0.0+incompatible",
					},
				},
			}},
			skip: true,
		},
		{
			desc: "remove subtle duplicates",
			in: []osvschema.Affected{{
				Package: osvschema.Package{
					Ecosystem: osvschema.EcosystemGo,
					Name:      "github.com/hashicorp/go-getter/v2",
				},
				Ranges: []osvschema.Range{{
					Type: osvschema.RangeEcosystem,
					Events: []osvschema.Event{
						{
							Introduced: "0",
						},
						{
							Fixed: "2.1.0",
						},
					},
				}},
			},
				{
					Package: osvschema.Package{
						Ecosystem: osvschema.EcosystemGo,
						Name:      "github.com/hashicorp/go-getter",
					},
					Ranges: []osvschema.Range{{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{
								Introduced: "2.0.0",
							},
							{
								Fixed: "2.1.0",
							},
						},
					}},
				}},
			want: []*report.Module{{
				Module: "github.com/hashicorp/go-getter/v2",
				Versions: []report.VersionRange{
					{
						Introduced: "2.0.0",
						Fixed:      "2.1.0",
					},
				},
			}},
			skip: true,
		},
	} {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			if tc.skip {
				t.Skip("skipping (not implemented yet)")
			}
			var gotNotes []string
			addNote := func(note string) {
				gotNotes = append(gotNotes, note)
			}
			got := affectedToModules(tc.in, addNote)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("affectedToModules() mismatch (-want +got)\n%s", diff)
			}
			if len(gotNotes) > 0 {
				t.Errorf("affectedToModules() output unexpected notes = %s", gotNotes)
			}
		})

	}
}
