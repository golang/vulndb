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
	db1, err := Load(dbname1)
	if err != nil {
		return err
	}
	db2, err := Load(dbname2)
	if err != nil {
		return err
	}
	diff := cmp.Diff(db1, db2)
	if diff == "" {
		diff = "(no change)"
	}
	fmt.Printf("diff (-db1, +db2):\n%s", diff)
	return nil
}
