// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cvelistrepo

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/test"
)

var update = flag.Bool("update", false, "update the .txtar files with real CVE data (this takes a while)")

var (
	v4txtar = "testdata/v4.txtar"
	v5txtar = "testdata/v5.txtar"
	cveIDs  = []string{
		"CVE-2021-0001",
		"CVE-2021-0010",
		"CVE-2021-1384",
		"CVE-2020-9283",
		"CVE-2022-39213",
	}
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *update {
		ctx := context.Background()
		if err := updateTxtar(ctx, v4txtar, URLv4, plumbing.HEAD, cveIDs); err != nil {
			fail(err)
		}
		if err := updateTxtar(ctx, v5txtar, URLv5, plumbing.Main, cveIDs); err != nil {
			fail(err)
		}
	}
	os.Exit(m.Run())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func updateTxtar(ctx context.Context, txtarFile, url string, ref plumbing.ReferenceName, cveIDs []string) error {
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
		id := cveschema5.FindCVE(f.Filename)
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
			return fmt.Errorf("could not update %s based on %q: no file for %s found", txtarFile, url, cveID)
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

	return test.WriteTxtar(txtarFile, arFiles,
		fmt.Sprintf("Repo in the shape of %q.\nUpdated with real data %s.\nAuto-generated; do not edit directly.",
			url, time.Now().Truncate(24*time.Hour).Format(time.RFC3339)))
}

func TestFiles(t *testing.T) {
	for _, tc := range []struct {
		name      string
		txtarFile string
		want      []File
	}{
		{
			name:      "v4",
			txtarFile: v4txtar,
			want: []File{
				{DirPath: "2020/9xxx", Filename: "CVE-2020-9283.json", Year: 2020, Number: 9283},
				{DirPath: "2021/0xxx", Filename: "CVE-2021-0001.json", Year: 2021, Number: 1},
				{DirPath: "2021/0xxx", Filename: "CVE-2021-0010.json", Year: 2021, Number: 10},
				{DirPath: "2021/1xxx", Filename: "CVE-2021-1384.json", Year: 2021, Number: 1384},
				{DirPath: "2022/39xxx", Filename: "CVE-2022-39213.json", Year: 2022, Number: 39213},
			},
		},
		{
			name:      "v5",
			txtarFile: v5txtar,
			want: []File{
				{DirPath: "cves/2020/9xxx", Filename: "CVE-2020-9283.json", Year: 2020, Number: 9283},
				{DirPath: "cves/2021/0xxx", Filename: "CVE-2021-0001.json", Year: 2021, Number: 1},
				{DirPath: "cves/2021/0xxx", Filename: "CVE-2021-0010.json", Year: 2021, Number: 10},
				{DirPath: "cves/2021/1xxx", Filename: "CVE-2021-1384.json", Year: 2021, Number: 1384},
				{DirPath: "cves/2022/39xxx", Filename: "CVE-2022-39213.json", Year: 2022, Number: 39213},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, commit, err := gitrepo.TxtarRepoAndHead(tc.txtarFile)
			if err != nil {
				t.Fatal(err)
			}

			got, err := Files(repo, commit)
			if err != nil {
				t.Fatal(err)
			}

			opt := cmpopts.IgnoreFields(File{}, "TreeHash", "BlobHash")
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(File{}), opt); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestFetchCVE(t *testing.T) {
	for _, tc := range []struct {
		name      string
		txtarFile string
		newCVE    func() CVE
	}{
		{
			name:      "v4",
			txtarFile: v4txtar,
			newCVE:    func() CVE { return new(cveschema.CVE) },
		},
		{
			name:      "v5",
			txtarFile: v5txtar,
			newCVE:    func() CVE { return new(cveschema5.CVERecord) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			repo, _, err := gitrepo.TxtarRepoAndHead(tc.txtarFile)
			if err != nil {
				t.Fatal(err)
			}

			for _, id := range cveIDs {
				t.Run(id, func(t *testing.T) {
					cve := tc.newCVE()
					if err := FetchCVE(ctx, repo, id, cve); err != nil {
						t.Fatal(err)
					}
					if got, want := cveID(cve), id; got != want {
						t.Errorf("FetchCVE(%s) ID = %s, want %s", id, got, want)
					}
				})
			}
		})
	}
}

func cveID(cve CVE) string {
	switch c := cve.(type) {
	case *cveschema5.CVERecord:
		return c.Metadata.ID
	case *cveschema.CVE:
		return c.Metadata.ID
	default:
		return "invalid"
	}
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		txtarFile string
		newCVE    func() CVE
	}{
		{
			name:      "v4",
			txtarFile: v4txtar,
			newCVE:    func() CVE { return new(cveschema.CVE) },
		},
		{
			name:      "v5",
			txtarFile: v5txtar,
			newCVE:    func() CVE { return new(cveschema5.CVERecord) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, commit, err := gitrepo.TxtarRepoAndHead(tc.txtarFile)
			if err != nil {
				t.Fatal(err)
			}

			files, err := Files(repo, commit)
			if err != nil {
				t.Fatal(err)
			}

			for _, file := range files {
				t.Run(file.Filename, func(t *testing.T) {
					cve := tc.newCVE()
					if err := Parse(repo, file, cve); err != nil {
						t.Fatal(err)
					}
					want := cveschema5.FindCVE(file.Filename)
					if got := cveID(cve); got != want {
						t.Errorf("ParseCVE(%s) ID = %s, want %s", file.Filename, got, want)
						t.Log(cve)
					}
				})
			}
		})
	}
}
