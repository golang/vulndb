// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gitrepo provides operations on git repos.
package gitrepo

import (
	"context"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/worker/log"
)

const CVEListRepoURL = "https://github.com/CVEProject/cvelist"

// Clone returns a repo by cloning the repo at repoURL.
func Clone(ctx context.Context, repoURL string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "gitrepo.Clone(%q)", repoURL)
	log.Infof(ctx, "Cloning repo %q at HEAD", repoURL)
	return git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.HEAD,
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	})
}

// Open returns a repo by opening the repo at the local path dirpath.
func Open(ctx context.Context, dirpath string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "gitrepo.Open(%q)", dirpath)
	log.Infof(ctx, "Opening repo at %q", dirpath)
	repo, err = git.PlainOpen(dirpath)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// CloneOrOpen clones repoPath if it is an HTTP(S) URL, or opens it from the
// local disk otherwise.
func CloneOrOpen(ctx context.Context, repoPath string) (*git.Repository, error) {
	if strings.HasPrefix(repoPath, "http://") || strings.HasPrefix(repoPath, "https://") {
		return Clone(ctx, repoPath)
	}
	return Open(ctx, repoPath)
}

// Root returns the root tree of the repo at HEAD.
func Root(repo *git.Repository) (root *object.Tree, err error) {
	refName := plumbing.HEAD
	ref, err := repo.Reference(refName, true)
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, err
	}
	return repo.TreeObject(commit.TreeHash)
}
