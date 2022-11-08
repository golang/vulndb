// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/derrors"
)

func Diff(dbname1, dbname2 string) (err error) {
	defer derrors.Wrap(&err, "Diff(%q, %q)", dbname1, dbname2)
	indexA, dbA, err := Load(dbname1)
	if err != nil {
		return fmt.Errorf("unable to load %q: %s", dbname1, err)
	}
	indexB, dbB, err := Load(dbname2)
	if err != nil {
		return fmt.Errorf("unable to load %q: %s", dbname2, err)
	}
	indexDiff := cmp.Diff(indexA, indexB)
	if indexDiff == "" {
		indexDiff = "(no change)"
	}
	dbDiff := cmp.Diff(dbA, dbB)
	if dbDiff == "" {
		dbDiff = "(no change)"
	}
	fmt.Printf("# index\n%s\n\n# db\n%s\n", indexDiff, dbDiff)
	return nil
}
