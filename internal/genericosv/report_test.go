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
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var (
	realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")
	update    = flag.Bool("update", false, "if true, update test YAML reports to reflect new expected behavior")
)

var (
	testdataDir = "testdata"
	testOSVDir  = filepath.Join(testdataDir, "osv")
	testYAMLDir = filepath.Join(testdataDir, "yaml")
)

// To update test cases to reflect new expected behavior
// (only use -proxy if the calls to the proxy will change):
// go test ./internal/genericosv/... -update -proxy -run TestToReport
func TestToReport(t *testing.T) {
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

			pc, err := proxy.NewTestClient(t, *realProxy)
			if err != nil {
				t.Fatal(err)
			}

			osv := &Entry{}
			if err := report.UnmarshalFromFile(path, osv); err != nil {
				t.Fatal(err)
			}

			got := report.New(osv, pc)
			// Keep record of what lints would apply to each generated report.
			got.LintAsNotes(pc)

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
