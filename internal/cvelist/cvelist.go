// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cvelist is used to fetch and parse information from
// https://github.com/CVEProject/cvelist
package cvelist

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/vulndb/internal/cveschema"
)

// Run clones the CVEProject/cvelist repository and compares the files to the
// existing triaged-cve-list.
func Run(triaged map[string]bool) error {
	// 1. Clone the repo.
	repo, root, err := cloneRepo(cvelistRepoURL)
	if err != nil {
		return err
	}
	return walkRepo(repo, root, "", triaged)
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

// walkRepo looks at the files in t, recursively, and check if it is a CVE that
// needs to be manually triaged.
func walkRepo(r *git.Repository, t *object.Tree, dirpath string, triaged map[string]bool) (err error) {
	var recent []object.TreeEntry
	for _, e := range t.Entries {
		if e.Mode == filemode.Dir && strings.HasPrefix(e.Name, "202") {
			recent = append(recent, e)
		}
	}
	for _, e := range recent {
		switch e.Mode {
		case filemode.Dir:
			dp := path.Join(dirpath, e.Name)
			t2, err := r.TreeObject(e.Hash)
			if err != nil {
				return err
			}
			if err := walkRepo(r, t2, dp, triaged); err != nil {
				return err
			}
		default:
			if !strings.HasPrefix(e.Name, "CVE-") {
				continue
			}
			cveID := strings.TrimSuffix(e.Name, ".json")
			if triaged[cveID] {
				continue
			}
			blob, err := r.BlobObject(e.Hash)
			if err != nil {
				return fmt.Errorf("r.BlobObject: %v", err)
			}
			src, err := blob.Reader()
			if err != nil {
				_ = src.Close()
				return fmt.Errorf("blob.Reader: %v", err)
			}
			_, err = parseCVE(src)
			if err != nil {
				_ = src.Close()
				filename := path.Join(dirpath, e.Name)
				return fmt.Errorf("parseCVE(%q, src): %v", filename, err)
			}
			// TODO: implement triage CVE logic
			if err := src.Close(); err != nil {
				return fmt.Errorf("src.Close: %v", err)
			}
		}
	}
	return nil
}

// parseCVEJSON parses a CVE file following the CVE JSON format:
// https://github.com/CVEProject/automation-working-group/blob/master/cve_json_schema/DRAFT-JSON-file-format-v4.md
func parseCVE(src io.Reader) (_ *cveschema.CVE, err error) {
	var c cveschema.CVE
	d := json.NewDecoder(src)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("d.Decode: %v", err)
	}
	return &c, nil
}
