// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package worker

import (
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/derrors"
)

// readTxtarRepo converts a txtar file to a single-commit
// repo.
func readTxtarRepo(filename string, now time.Time) (_ *git.Repository, err error) {
	defer derrors.Wrap(&err, "readTxtarRepo(%q)", filename)

	mfs := memfs.New()
	ar, err := txtar.ParseFile(filename)
	if err != nil {
		return nil, err
	}
	for _, f := range ar.Files {
		file, err := mfs.Create(f.Name)
		if err != nil {
			return nil, err
		}
		if _, err := file.Write(f.Data); err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}

	repo, err := git.Init(memory.NewStorage(), mfs)
	if err != nil {
		return nil, err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	for _, f := range ar.Files {
		if _, err := wt.Add(f.Name); err != nil {
			return nil, err
		}
	}
	_, err = wt.Commit("", &git.CommitOptions{All: true, Author: &object.Signature{
		Name:  "Joe Random",
		Email: "joe@example.com",
		When:  now,
	}})
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// headCommit returns the commit at the repo HEAD.
func headCommit(t *testing.T, repo *git.Repository) *object.Commit {
	h, err := headHash(repo)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(h)
	if err != nil {
		t.Fatal(err)
	}
	return commit
}

// headHash returns the hash of the repo's HEAD.
func headHash(repo *git.Repository) (plumbing.Hash, error) {
	ref, err := repo.Reference(plumbing.HEAD, true)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return ref.Hash(), nil
}
