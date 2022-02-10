// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gitrepo provides operations on git repos.
package gitrepo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/exp/event"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/worker/log"
)

// Clone returns a repo by cloning the repo at repoURL.
func Clone(ctx context.Context, repoURL string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "gitrepo.Clone(%q)", repoURL)
	ctx = event.Start(ctx, "gitrepo.Clone")
	defer event.End(ctx)

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
	ctx = event.Start(ctx, "gitrepo.Open")
	defer event.End(ctx)

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

// ReadTxtarRepo converts a txtar file to a single-commit
// repo. It is intended for testing.
func ReadTxtarRepo(filename string, now time.Time) (_ *git.Repository, err error) {
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

// HeadHash returns the hash of the repo's HEAD.
func HeadHash(repo *git.Repository) (plumbing.Hash, error) {
	ref, err := repo.Reference(plumbing.HEAD, true)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return ref.Hash(), nil
}

// ParseGitHubRepo parses a string of the form owner/repo or
// github.com/owner/repo.
func ParseGitHubRepo(s string) (owner, repoName string, err error) {
	parts := strings.Split(s, "/")
	switch len(parts) {
	case 2:
		return parts[0], parts[1], nil
	case 3:
		if parts[0] != "github.com" {
			return "", "", fmt.Errorf("%q is not in the form {github.com/}owner/repo", s)
		}
		return parts[1], parts[2], nil
	default:
		return "", "", fmt.Errorf("%q is not in the form {github.com/}owner/repo", s)
	}
}

// FileHistory calls f for every commit in filepath's history, starting from refName.
func FileHistory(repo *git.Repository, refName plumbing.ReferenceName, filepath string, f func(*object.Commit) error) error {
	ref, err := repo.Reference(refName, true)
	if err != nil {
		return err
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return err
	}
	return object.NewCommitFileIterFromIter(
		filepath,
		object.NewCommitPreorderIter(commit, nil, nil),
		false,
	).ForEach(f)
}

// CommitDates returns the oldest and newest commit date for filepath in origin/master.
func CommitDates(repo *git.Repository, filepath string) (oldest, newest time.Time, err error) {
	defer derrors.Wrap(&err, "CommitDates(%q)", filepath)

	refName := plumbing.NewRemoteReferenceName("origin", "master")
	err = FileHistory(repo, refName, filepath, func(commit *object.Commit) error {
		when := commit.Committer.When.UTC()
		if oldest.IsZero() || when.Before(oldest) {
			oldest = when
		}
		if when.After(newest) {
			newest = when
		}
		return nil
	})
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return oldest, newest, nil
}
