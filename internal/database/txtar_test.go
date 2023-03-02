// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/tools/txtar"
)

// Helper functions for working with txtar files in tests.

const (
	validTxtar           = "testdata/db.txtar"
	smallTxtar           = "testdata/db-small.txtar"
	invalidDBMetaTxtar   = "testdata/invalid-db-meta.txtar"
	invalidModulesTxtar  = "testdata/invalid-modules.txtar"
	invalidVulnsTxtar    = "testdata/invalid-vulns.txtar"
	invalidFilenameTxtar = "testdata/invalid-filename.txtar"
	invalidEntriesTxtar  = "testdata/invalid-entries.txtar"

	vulndbTxtar = "testdata/vulndb-repo.txtar"
)

// data returns the raw JSON data contained in the pseudofile filename,
// with any whitespace removed.
//
// This a test helper function.
func data(ar *txtar.Archive, filename string) ([]byte, error) {
	for _, f := range ar.Files {
		if f.Name == filename {
			return removeWhitespace(f.Data)
		}
	}
	return nil, fmt.Errorf("file %s not found", filename)
}

// txtarToDir writes the contents of a txtar file into a directory dir,
// removing any whitespace from the contents.
// It assumes that all "files" in the txtar file contain json.
// If gzip is true, it adds a corresponding gzipped file for each file present.
//
// This a test helper function.
func txtarToDir(filename string, dir string, gzip bool) error {
	ar, err := txtar.ParseFile(filename)
	if err != nil {
		return err
	}

	for _, f := range ar.Files {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(f.Name)), 0755); err != nil {
			return err
		}
		data, err := removeWhitespace(f.Data)
		if err != nil {
			return err
		}
		fname := filepath.Join(dir, f.Name)
		if err := os.WriteFile(fname, data, 0644); err != nil {
			return err
		}
		if gzip {
			if err := writeGzipped(fname+".gz", data); err != nil {
				return err
			}
		}
	}

	return nil
}

func removeWhitespace(data []byte) ([]byte, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
