// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cvelist is used to fetch and parse information from
// https://github.com/CVEProject/cvelist
package cvelist

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

// Run clones the CVEProject/cvelist repository and compares the files to the
// existing triaged-cve-list.
func Run(triaged map[string]bool) error {
	// 1. Clone the repo.
	_, _, err := cloneRepo(cvelistRepoURL)
	if err != nil {
		return err
	}
	// 2. TODO: walk the repo and figure out if something is a CVE.
	return nil
}

const cvelistRepoURL = "https://github.com/CVEProject/cvelist"

// cloneRepo returns a repo and tree object for the repo at HEAD by
// cloning the repo at repoURL.
func cloneRepo(repoURL string) (repo *git.Repository, root *object.Tree, err error) {
	repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.HEAD,
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	})
	if err != nil {
		return nil, nil, err
	}
	refName := plumbing.HEAD
	ref, err := repo.Reference(refName, true)
	if err != nil {
		return nil, nil, err
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, nil, err
	}
	root, err = repo.TreeObject(commit.TreeHash)
	if err != nil {
		return nil, nil, err
	}
	return repo, root, nil
}
