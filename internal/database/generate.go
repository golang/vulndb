// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"context"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
)

// Generate creates and writes a new Go vulnerability database to outDir
// based on the contents of the "data/osv" folder inside repoDir, a local
// git repo.
//
// repoDir must contain a "data/osv" folder to with files in
// OSV JSON format with filenames of the form GO-YYYY-XXXX.json.
func Generate(ctx context.Context, repoDir, outDir string, indent bool) (err error) {
	defer derrors.Wrap(&err, "Generate(%q)", repoDir)

	repo, err := gitrepo.Open(ctx, repoDir)
	if err != nil {
		return err
	}
	new, err := New(ctx, repo)
	if err != nil {
		return err
	}
	if err = new.Write(outDir, false); err != nil {
		return err
	}

	return nil
}
