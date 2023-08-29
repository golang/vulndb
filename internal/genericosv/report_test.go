// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genericosv

import (
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	osvschema "github.com/google/osv-scanner/pkg/models"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var (
	realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")
	update    = flag.Bool("update", false, "if true, update test YAML reports to reflect new expected behavior")
)

var (
	testdataDir        = "testdata"
	testOSVDir         = filepath.Join(testdataDir, "osv")
	testYAMLDir        = filepath.Join(testdataDir, "yaml")
	proxyResponsesFile = filepath.Join(testdataDir, "proxy.json")
)

// To update test cases to reflect new expected behavior:
// go test ./internal/genericosv/... -update -run TestToReport
func TestToReport(t *testing.T) {
	if *realProxy {
		defer func() {
			err := updateProxyResponses(proxy.DefaultClient)
			if err != nil {
				t.Fatal(err)
			}
		}()
	} else {
		err := setupMockProxy(t)
		if err != nil {
			t.Fatal(err)
		}
	}

	// The outer test run forces the test to wait for all parallel tests
	// to finish before tearing down test.
	t.Run("run", func(t *testing.T) {
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

				got := osv.ToReport("GO-TEST-ID", proxy.DefaultClient)
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
	})
}

// TODO(https://go.dev/issues/61769): unskip test cases as we add features.
func TestAffectedToModules(t *testing.T) {
	pc := proxy.DefaultClient
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
			got := affectedToModules(tc.in, addNote, pc)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("affectedToModules() mismatch (-want +got)\n%s", diff)
			}
			if len(gotNotes) > 0 {
				t.Errorf("affectedToModules() output unexpected notes = %s", gotNotes)
			}
		})

	}
}

// Use saved responses from testdata/proxy.json instead of real proxy calls.
func setupMockProxy(t *testing.T) error {
	t.Helper()

	b, err := os.ReadFile(proxyResponsesFile)
	if err != nil {
		return err
	}
	var responses map[string]*proxy.Response
	err = json.Unmarshal(b, &responses)
	if err != nil {
		return err
	}

	defaultProxyClient := proxy.DefaultClient
	testClient, cleanup := proxy.NewTestClient(responses)
	proxy.DefaultClient = testClient
	t.Cleanup(cleanup)
	t.Cleanup(func() {
		proxy.DefaultClient = defaultProxyClient
	})

	return nil
}

// Write proxy responses for this run to testdata/proxy.json.
func updateProxyResponses(pc *proxy.Client) error {
	responses, err := json.MarshalIndent(pc.Responses(), "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(proxyResponsesFile, responses, 0644)
}
