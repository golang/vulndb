// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cvelistrepo

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/test"
)

// WriteTxtarRepo downloads the given CVEs from the CVE list (v4 or v5) in url,
// and writes them as a txtar repo to filename.
//
// Intended for testing.
func WriteTxtarRepo(ctx context.Context, url string, filename string, cveIDs []string) error {
	var ref plumbing.ReferenceName

	switch url {
	case URLv5:
		ref = plumbing.Main
	default:
		ref = plumbing.HEAD
	}

	repo, err := gitrepo.CloneAt(ctx, url, ref)
	if err != nil {
		return err
	}

	commit, err := gitrepo.HeadCommit(repo)
	if err != nil {
		return err
	}

	files, err := Files(repo, commit)
	if err != nil {
		return err
	}

	idToFile := make(map[string]*File)
	for _, f := range files {
		f := f
		id := cveschema5.FindCVE(f.Filename)
		if id != "" {
			if _, ok := idToFile[id]; ok {
				return fmt.Errorf("found duplicate record files for %s", id)
			}
			idToFile[id] = &f
		}
	}

	arFiles := make([]txtar.File, 0, len(cveIDs))
	arFiles = append(arFiles, txtar.File{
		Name: "README.md",
		Data: []byte("ignore me please\n\n"),
	})

	for _, cveID := range cveIDs {
		f, ok := idToFile[cveID]
		if !ok {
			return fmt.Errorf("could not write %s based on %q: no file for %s found", filename, url, cveID)
		}

		b, err := f.ReadAll(repo)
		if err != nil {
			return err
		}

		arFiles = append(arFiles, txtar.File{
			Name: path.Join(f.DirPath, f.Filename),
			Data: b,
		})
	}

	return test.WriteTxtar(filename, arFiles,
		fmt.Sprintf("Repo in the shape of %q.\nUpdated with real data %s.\nAuto-generated; do not edit directly.",
			url, time.Now().Truncate(24*time.Hour).Format(time.RFC3339)))
}
