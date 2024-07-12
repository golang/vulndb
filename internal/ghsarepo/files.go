// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ghsarepo

import (
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/idstr"
)

type File struct {
	Path     string
	BlobHash plumbing.Hash
}

func Files(repo *git.Repository, commit *object.Commit) (files []*File, _ error) {
	const reviewed = "advisories/github-reviewed"
	root, err := gitrepo.RootAt(repo, commit)
	if err != nil {
		return nil, err
	}
	e, err := root.FindEntry(reviewed)
	if err != nil {
		return nil, err
	}
	tree, err := repo.TreeObject(e.Hash)
	if err != nil {
		return nil, err
	}
	if err := tree.Files().ForEach(func(f *object.File) error {
		files = append(files, &File{
			Path:     f.Name,
			BlobHash: f.Hash,
		})
		return nil
	}); err != nil {
		return nil, err
	}

	return files, nil
}

func (f *File) ID() string {
	return idstr.FindGHSA(f.Path)
}

func (f *File) Name() string {
	return filepath.Base(f.Path)
}

func (f *File) ReadAll(repo *git.Repository) ([]byte, error) {
	return gitrepo.ReadAll(repo, f.BlobHash)
}
