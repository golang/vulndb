// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cvelistrepo

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/maps"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/test"
	"gopkg.in/yaml.v3"
)

var (
	txtarRepo = filepath.Join(testdata, "cvelist.txtar")
	testdata  = filepath.Join("testdata", "cve")
	testCVEs  = map[string]string{
		// First-party CVEs not assigned by the Go CNA.
		// (These were created before Go was a CNA).
		"CVE-2020-9283":  "golang.org/x/crypto",
		"CVE-2021-27919": "archive/zip",
		"CVE-2021-3115":  "cmd/go",

		// Third party CVEs, assigned by other CNAs.
		"CVE-2022-39213": "github.com/pandatix/go-cvss",
		"CVE-2023-44378": "github.com/Consensys/gnark",
		"CVE-2023-45141": "github.com/gofiber/fiber",
		"CVE-2024-2056":  "github.com/gvalkov/tailon",
		"CVE-2024-33522": "github.com/projectcalico/calico",

		// A third-party non-Go CVE that was miscategorized
		// as applying to "github.com/amlweems/xzbot".
		"CVE-2024-3094": "github.com/amlweems/xzbot",

		// First-party CVEs, assigned by the Go CNA.
		"CVE-2023-29407": "golang.org/x/image",
		"CVE-2023-45283": "path/filepath",
		"CVE-2023-45285": "cmd/go",

		// A third-party CVE assigned by the Go CNA.
		"CVE-2023-45286": "github.com/go-resty/resty/v2",
	}
	testTime = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
)

func UpdateTxtar(ctx context.Context, t *testing.T, url string) {
	ids := maps.Keys(testCVEs)
	slices.Sort(ids)
	if err := writeTxtarRepo(ctx, url, txtarRepo, ids); err != nil {
		t.Fatal(err)
	}
}

func TestToReport[S report.Source](t *testing.T, update, realProxy bool) error {
	pc, err := proxy.NewTestClient(t, realProxy)
	if err != nil {
		t.Fatal(err)
	}

	if update {
		if err := os.RemoveAll(filepath.Join(testdata, t.Name())); err != nil {
			t.Fatal(err)
		}
	}

	repo, commit, err := gitrepo.TxtarRepoAndHead(txtarRepo)
	if err != nil {
		return err
	}
	files, err := Files(repo, commit)
	if err != nil {
		return err
	}

	for _, file := range files {
		id := idstr.FindCVE(file.Filename)
		t.Run(id, func(t *testing.T) {
			cve, err := Parse[S](repo, file)
			if err != nil {
				t.Fatalf("Parse(%s)=%s", id, err)
			}

			mp, ok := testCVEs[id]
			if !ok {
				t.Fatalf("%s not found in testCVEs", id)
			}

			r := report.New(cve, pc, report.WithModulePath(mp),
				report.WithCreated(testTime))
			// Keep record of what lints would apply to each generated report.
			r.LintAsNotes(pc)
			b, err := yaml.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}

			tf := filepath.Join(testdata, t.Name()+".txtar")

			if update {
				if err := test.WriteTxtar(tf, []txtar.File{
					{
						Name: id,
						Data: b,
					},
				}, fmt.Sprintf("Expected output of %s.", t.Name())); err != nil {
					t.Fatal(err)
				}
			}

			ar, err := txtar.ParseFile(tf)
			if err != nil {
				t.Fatal(err)
			}

			for _, af := range ar.Files {
				if af.Name != id {
					t.Errorf("unexpected archive file %s", af.Name)
					continue
				}
				want, got := string(b), string(af.Data)
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("%s content mismatch (-want, +got):\n%s", af.Name, diff)
				}
			}
		})
	}

	return nil
}

// writeTxtarRepo downloads the given CVEs from the CVE list (v4 or v5) in url,
// and writes them as a txtar repo to filename.
//
// Intended for testing.
func writeTxtarRepo(ctx context.Context, url string, filename string, cveIDs []string) error {
	var ref plumbing.ReferenceName

	switch url {
	case URLv5:
		ref = plumbing.Main
	default:
		ref = plumbing.HEAD
	}

	repo, err := gitrepo.CloneAt(ctx, url, ref)
	if err != nil {
		return err
	}

	commit, err := gitrepo.HeadCommit(repo)
	if err != nil {
		return err
	}

	files, err := Files(repo, commit)
	if err != nil {
		return err
	}

	idToFile := make(map[string]*File)
	for _, f := range files {
		f := f
		id := idstr.FindCVE(f.Filename)
		if id != "" {
			if _, ok := idToFile[id]; ok {
				return fmt.Errorf("found duplicate record files for %s", id)
			}
			idToFile[id] = &f
		}
	}

	arFiles := make([]txtar.File, 0, len(cveIDs))
	arFiles = append(arFiles, txtar.File{
		Name: "README.md",
		Data: []byte("ignore me please\n\n"),
	})

	for _, cveID := range cveIDs {
		f, ok := idToFile[cveID]
		if !ok {
			return fmt.Errorf("could not write %s based on %q: no file for %s found", filename, url, cveID)
		}

		b, err := f.ReadAll(repo)
		if err != nil {
			return err
		}

		arFiles = append(arFiles, txtar.File{
			Name: path.Join(f.DirPath, f.Filename),
			Data: b,
		})
	}

	return test.WriteTxtar(filename, arFiles,
		fmt.Sprintf("Repo in the shape of %q.\nUpdated with real data %s.\nAuto-generated; do not edit directly.",
			url, time.Now().Truncate(24*time.Hour).Format(time.RFC3339)))
}
