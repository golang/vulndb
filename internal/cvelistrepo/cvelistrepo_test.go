// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cvelistrepo

import (
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/gitrepo"
)

func TestRepoCVEFiles(t *testing.T) {
	repo, err := gitrepo.ReadTxtarRepo("testdata/basic.txtar", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commit := headCommit(t, repo)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Files(repo, commit)
	if err != nil {
		t.Fatal(err)
	}

	want := []File{
		{DirPath: "2020/9xxx", Filename: "CVE-2020-9283.json", Year: 2020, Number: 9283},
		{DirPath: "2021/0xxx", Filename: "CVE-2021-0001.json", Year: 2021, Number: 1},
		{DirPath: "2021/0xxx", Filename: "CVE-2021-0010.json", Year: 2021, Number: 10},
		{DirPath: "2021/1xxx", Filename: "CVE-2021-1384.json", Year: 2021, Number: 1384},
	}

	opt := cmpopts.IgnoreFields(File{}, "TreeHash", "BlobHash")
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(File{}), opt); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

// headCommit returns the commit at the repo HEAD.
func headCommit(t *testing.T, repo *git.Repository) *object.Commit {
	h, err := gitrepo.HeadHash(repo)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(h)
	if err != nil {
		t.Fatal(err)
	}
	return commit
}
