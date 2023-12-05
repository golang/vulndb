// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/maps"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/test"
	"gopkg.in/yaml.v3"
)

var (
	updateGolden     = flag.Bool("update", false, "update golden files")
	updateTxtarRepos = flag.Bool("update-repo", false, "update the test repos ({v4,v5}.txtar) with real CVE data - this takes a while")
)

var (
	testdata = filepath.Join("testdata", "cve")
	v4txtar  = filepath.Join(testdata, "v4.txtar")
	v5txtar  = filepath.Join(testdata, "v5.txtar")
	testCVEs = map[string]string{
		"CVE-2020-9283":  "golang.org/x/crypto",
		"CVE-2022-39213": "github.com/pandatix/go-cvss",
		"CVE-2023-44378": "github.com/Consensys/gnark",
		"CVE-2023-45141": "github.com/gofiber/fiber",
	}
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *updateTxtarRepos {
		ctx := context.Background()
		ids := maps.Keys(testCVEs)
		if err := cvelistrepo.WriteTxtarRepo(ctx, cvelistrepo.URLv4, v4txtar, ids); err != nil {
			fail(err)
		}
		if err := cvelistrepo.WriteTxtarRepo(ctx, cvelistrepo.URLv5, v5txtar, ids); err != nil {
			fail(err)
		}
	}
	os.Exit(m.Run())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

const placeholderID = "PLACEHOLDER-ID"

func TestCVEToReport(t *testing.T) {
	newV4 := func() cvelistrepo.CVE {
		return new(cveschema.CVE)
	}
	toReportV4 := func(cve cvelistrepo.CVE, modulePath string) *Report {
		return cveToReport(cve.(*cveschema.CVE), placeholderID, modulePath)
	}
	if err := run(t, v4txtar, newV4, toReportV4); err != nil {
		t.Fatal(err)
	}
}

func TestCVE5ToReport(t *testing.T) {
	newV5 := func() cvelistrepo.CVE {
		return new(cveschema5.CVERecord)
	}
	toReportV5 := func(cve cvelistrepo.CVE, modulePath string) *Report {
		return cve5ToReport(cve.(*cveschema5.CVERecord), placeholderID, modulePath)
	}
	if err := run(t, v5txtar, newV5, toReportV5); err != nil {
		t.Fatal(err)
	}
}

// Check that the created report is the same for v4 and v5.
// This is a transitional test that will be removed once we are OK
// with divergence between v4 and v5, or if we remove support for v4 entirely.
func TestV4V5Equivalence(t *testing.T) {
	if err := filepath.WalkDir(filepath.Join(testdata, "TestCVE5ToReport"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		fname := filepath.Base(path)
		t.Run(fname, func(t *testing.T) {
			v5b, err := findCVEFile(path)
			if err != nil {
				t.Fatal(err)
			}
			v4file := filepath.Join(testdata, "TestCVEToReport", fname)
			v4b, err := findCVEFile(v4file)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(v4b, v5b); diff != "" {
				t.Errorf("mismatch (-v4, +v5):\n%s", diff)
			}
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func findCVEFile(tf string) (*txtar.File, error) {
	ar, err := txtar.ParseFile(tf)
	if err != nil {
		return nil, err
	}
	for _, af := range ar.Files {
		if cveschema5.IsCVE(af.Name) {
			return &af, nil
		}
	}
	return nil, fmt.Errorf("%s: cve archive file not found", tf)
}

func run(t *testing.T, txtarFile string, newCVE func() cvelistrepo.CVE, toReport func(cvelistrepo.CVE, string) *Report) error {
	if *updateGolden {
		if err := os.RemoveAll(filepath.Join(testdata, t.Name())); err != nil {
			t.Fatal(err)
		}
	}

	repo, commit, err := gitrepo.TxtarRepoAndHead(txtarFile)
	if err != nil {
		return err
	}
	files, err := cvelistrepo.Files(repo, commit)
	if err != nil {
		return err
	}

	for _, file := range files {
		id := cveschema5.FindCVE(file.Filename)
		t.Run(id, func(t *testing.T) {
			cve := newCVE()
			if err := cvelistrepo.Parse(repo, file, cve); err != nil {
				t.Fatalf("Parse(%s)=%s", id, err)
			}

			mp, ok := testCVEs[id]
			if !ok {
				t.Fatalf("%s not found in testCVEs", id)
			}

			b, err := yaml.Marshal(toReport(cve, mp))
			if err != nil {
				t.Fatal(err)
			}

			tf := filepath.Join(testdata, t.Name()+".txtar")

			if *updateGolden {
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
