// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cvelistrepo

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/report"
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
		if err := writeTxtarRepo(ctx, URLv4, v4txtar, cveIDs); err != nil {
			fail(err)
		}
		if err := writeTxtarRepo(ctx, URLv5, v5txtar, cveIDs); err != nil {
			fail(err)
		}
	}
	os.Exit(m.Run())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
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

func TestParse(t *testing.T) {
	testParse[*cve4.CVE](t, "v4", v4txtar)
	testParse[*cve5.CVERecord](t, "v5", v5txtar)
}

func testParse[S report.Source](t *testing.T, name, txtarFile string) {
	t.Run(name, func(t *testing.T) {
		repo, commit, err := gitrepo.TxtarRepoAndHead(txtarFile)
		if err != nil {
			t.Fatal(err)
		}

		files, err := Files(repo, commit)
		if err != nil {
			t.Fatal(err)
		}

		for _, file := range files {
			t.Run(file.Filename, func(t *testing.T) {
				cve, _, err := gitrepo.Parse[S](repo, &file)
				if err != nil {
					t.Fatal(err)
				}
				want := idstr.FindCVE(file.Filename)
				if got := cve.SourceID(); got != want {
					t.Errorf("ParseCVE(%s) ID = %s, want %s", file.Filename, got, want)
					t.Log(cve)
				}
			})
		}
	})
}
