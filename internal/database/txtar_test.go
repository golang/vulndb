// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"bytes"
	"encoding/json"
	"fmt"

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

func removeWhitespace(data []byte) ([]byte, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
