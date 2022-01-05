// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cvelistrepo supports working with the repo
// containing the list of CVEs.
package cvelistrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
)

// URL is the URL of the cvelist repo.
const URL = "https://github.com/CVEProject/cvelist"

// A File is a file in the cvelist repo that contains a CVE.
type File struct {
	DirPath  string
	Filename string
	TreeHash plumbing.Hash
	BlobHash plumbing.Hash
	Year     int
	Number   int
}

// Files returns all the CVE files in the given repo commit, sorted by
// name.
func Files(repo *git.Repository, commit *object.Commit) (_ []File, err error) {
	defer derrors.Wrap(&err, "CVEFiles(%s)", commit.Hash)

	root, err := repo.TreeObject(commit.TreeHash)
	if err != nil {
		return nil, fmt.Errorf("TreeObject: %v", err)
	}
	files, err := walkFiles(repo, root, "", nil)
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		// Compare the year and the number, as ints. Using the ID directly
		// would put CVE-2014-100009 before CVE-2014-10001.
		if files[i].Year != files[j].Year {
			return files[i].Year < files[j].Year
		}
		return files[i].Number < files[j].Number
	})
	return files, nil
}

// walkFiles collects CVE files from a repo tree.
func walkFiles(repo *git.Repository, tree *object.Tree, dirpath string, files []File) ([]File, error) {
	for _, e := range tree.Entries {
		if e.Mode == filemode.Dir {
			dir, err := repo.TreeObject(e.Hash)
			if err != nil {
				return nil, err
			}
			files, err = walkFiles(repo, dir, path.Join(dirpath, e.Name), files)
			if err != nil {
				return nil, err
			}
		} else if isCVEFilename(e.Name) {
			// e.Name is CVE-YEAR-NUMBER.json
			year, err := strconv.Atoi(e.Name[4:8])
			if err != nil {
				return nil, err
			}
			number, err := strconv.Atoi(e.Name[9 : len(e.Name)-5])
			if err != nil {
				return nil, err
			}
			files = append(files, File{
				DirPath:  dirpath,
				Filename: e.Name,
				TreeHash: tree.Hash,
				BlobHash: e.Hash,
				Year:     year,
				Number:   number,
			})
		}
	}
	return files, nil
}

// isCVEFilename reports whether name is the basename of a CVE file.
func isCVEFilename(name string) bool {
	return strings.HasPrefix(name, "CVE-") && path.Ext(name) == ".json"
}

// blobReader returns a reader to the blob with the given hash.
func blobReader(repo *git.Repository, hash plumbing.Hash) (io.Reader, error) {
	blob, err := repo.BlobObject(hash)
	if err != nil {
		return nil, err
	}
	return blob.Reader()
}

// FetchCVE fetches the CVE file for cveID from the CVElist repo and returns
// the parsed info.
func FetchCVE(ctx context.Context, repoPath, cveID string) (_ *cveschema.CVE, err error) {
	defer derrors.Wrap(&err, "FetchCVE(repo, commit, %s)", cveID)
	repo, err := gitrepo.CloneOrOpen(ctx, repoPath)
	if err != nil {
		return nil, err
	}
	ref, err := repo.Reference(plumbing.HEAD, true)
	if err != nil {
		return nil, err
	}
	ch := ref.Hash()
	commit, err := repo.CommitObject(ch)
	if err != nil {
		return nil, err
	}
	files, err := Files(repo, commit)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if strings.Contains(f.Filename, cveID) {
			cve, err := ParseCVE(repo, f)
			if err != nil {
				return nil, err
			}
			return cve, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

// ParseCVE parses the CVE file f into a CVE.
func ParseCVE(repo *git.Repository, f File) (*cveschema.CVE, error) {
	// Read CVE from repo.
	r, err := blobReader(repo, f.BlobHash)
	if err != nil {
		return nil, err
	}
	cve := &cveschema.CVE{}
	if err := json.NewDecoder(r).Decode(cve); err != nil {
		return nil, err
	}
	return cve, nil
}
