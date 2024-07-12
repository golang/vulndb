// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gitrepo provides operations on git repos.
package gitrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/observe"
	"golang.org/x/vulndb/internal/worker/log"
)

// Clone returns a bare repo by cloning the repo at repoURL.
func Clone(ctx context.Context, repoURL string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "gitrepo.Clone(%q)", repoURL)
	ctx, span := observe.Start(ctx, "gitrepo.Clone")
	defer span.End()

	return CloneAt(ctx, repoURL, plumbing.HEAD)
}

// Clone returns a bare repo by cloning the repo at repoURL at the given ref.
func CloneAt(ctx context.Context, repoURL string, ref plumbing.ReferenceName) (repo *git.Repository, err error) {
	log.Infof(ctx, "Cloning repo %q at %s", repoURL, ref)
	return git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: ref,
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	})
}

// PlainClone returns a (non-bare) repo with its history by cloning the repo at repoURL.
func PlainClone(ctx context.Context, dir, repoURL string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "gitrepo.PlainClone(%q)", repoURL)
	ctx, span := observe.Start(ctx, "gitrepo.PlainClone")
	defer span.End()

	log.Infof(ctx, "Plain cloning repo %q at HEAD", repoURL)
	return git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.HEAD,
		SingleBranch:  true, // allow branches other than master
		Depth:         0,    // pull in history
		Tags:          git.NoTags,
	})
}

// PlainCloneWith returns a (non-bare) repo with its history by cloning the repo with the given options opt.
func PlainCloneWith(ctx context.Context, dir string, opts *git.CloneOptions) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "gitrepo.PlainCloneWith(%q)", opts.URL)
	ctx, span := observe.Start(ctx, "gitrepo.PlainCloneWith")
	defer span.End()

	log.Infof(ctx, "Plain cloning repo %q at HEAD with options", opts.URL)
	return git.PlainCloneContext(ctx, dir, false, opts)
}

// Open returns a repo by opening the repo at the local path dirpath.
func Open(ctx context.Context, dirpath string) (repo *git.Repository, err error) {
	defer derrors.Wrap(&err, "gitrepo.Open(%q)", dirpath)
	ctx, span := observe.Start(ctx, "gitrepo.Open")
	defer span.End()

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
	head, err := HeadCommit(repo)
	if err != nil {
		return nil, err
	}
	return RootAt(repo, head)
}

// Root returns the root tree of the repo at the given commit.
func RootAt(repo *git.Repository, commit *object.Commit) (root *object.Tree, err error) {
	return repo.TreeObject(commit.TreeHash)
}

// TxtarRepoAndHead reads a txtar repo into a single-commit repository,
// and returns the repo and its head commit.
// Intended for testing.
func TxtarRepoAndHead(file string) (*git.Repository, *object.Commit, error) {
	repo, err := ReadTxtarRepo(file, time.Now())
	if err != nil {
		return nil, nil, err
	}
	commit, err := HeadCommit(repo)
	if err != nil {
		return nil, nil, err
	}
	return repo, commit, nil
}

// HeadCommit returns the commit at the repo HEAD.
func HeadCommit(repo *git.Repository) (*object.Commit, error) {
	h, err := HeadHash(repo)
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(h)
	if err != nil {
		return nil, err
	}
	return commit, nil
}

// ReadTxtarRepo converts a txtar file to a single-commit
// repo. It is intended for testing.
func ReadTxtarRepo(filename string, now time.Time) (_ *git.Repository, err error) {
	defer derrors.Wrap(&err, "ReadTxtarRepo(%q)", filename)

	ar, err := txtar.ParseFile(filename)
	if err != nil {
		return nil, err
	}

	return FromTxtarArchive(ar, now)
}

func FromTxtarArchive(ar *txtar.Archive, now time.Time) (_ *git.Repository, err error) {
	mfs := memfs.New()
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

// ReferenceName is a git reference.
type ReferenceName struct{ plumbing.ReferenceName }

var (
	HeadReference = ReferenceName{plumbing.HEAD}                                       // HEAD
	MainReference = ReferenceName{plumbing.NewRemoteReferenceName("origin", "master")} // origin/master
)

// Dates is the oldest and newest commit timestamps for a file.
type Dates struct {
	Oldest, Newest time.Time
}

// AllCommitDates returns the oldest and newest commit timestamps for every
// file in the repo at the given reference, where the filename begins with
// prefix. The supplied prefix should include the trailing /.
func AllCommitDates(repo *git.Repository, refName ReferenceName, prefix string) (dates map[string]Dates, err error) {
	defer derrors.Wrap(&err, "AllCommitDates(%q)", prefix)

	ref, err := repo.Reference(refName.ReferenceName, true)
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, err
	}
	dates = make(map[string]Dates)
	iter := object.NewCommitPreorderIter(commit, nil, nil)
	commit, err = iter.Next()
	if err != nil {
		return nil, err
	}
	for commit != nil {
		parentCommit, err := iter.Next()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			parentCommit = nil
		}

		currentTree, err := commit.Tree()
		if err != nil {
			return nil, err
		}

		var parentTree *object.Tree
		if parentCommit != nil {
			parentTree, err = parentCommit.Tree()
			if err != nil {
				return nil, err
			}
		}

		changes, err := object.DiffTree(currentTree, parentTree)
		if err != nil {
			return nil, err
		}

		for _, change := range changes {
			name := change.To.Name
			if change.From.Name != "" {
				name = change.From.Name
			}
			when := commit.Committer.When.UTC()
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			d := dates[name]
			if d.Oldest.IsZero() || when.Before(d.Oldest) {
				if d.Oldest.After(d.Newest) {
					d.Newest = d.Oldest
				}
				d.Oldest = when
			}
			if when.After(d.Newest) {
				d.Newest = when
			}
			dates[name] = d
		}

		commit = parentCommit
	}
	return dates, nil
}

func ReadAll(repo *git.Repository, hash plumbing.Hash) ([]byte, error) {
	blob, err := repo.BlobObject(hash)
	if err != nil {
		return nil, err
	}
	r, err := blob.Reader()
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

type File interface {
	Name() string
	ReadAll(*git.Repository) ([]byte, error)
}

// Parse unmarshals the contents of f.
func Parse[T any](repo *git.Repository, f File) (_ T, raw []byte, _ error) {
	var zero T
	b, err := f.ReadAll(repo)
	if err != nil {
		return zero, nil, err
	}
	if len(b) == 0 {
		return zero, nil, fmt.Errorf("%s is empty", f.Name())
	}
	v := new(T)
	if err := json.Unmarshal(b, v); err != nil {
		return zero, nil, err
	}
	return *v, b, nil
}
