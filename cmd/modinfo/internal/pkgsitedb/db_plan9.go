// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build plan9

package pkgsitedb

import (
	"context"
	"database/sql"
	"errors"

	"golang.org/x/pkgsite-metrics/internal/config"
	"golang.org/x/pkgsite-metrics/internal/scan"
)

var errDoesNotCompile = errors.New("github.com/lib/pq does not compile on plan9")

func Open(ctx context.Context, cfg *config.Config) (_ *sql.DB, err error) {
	return nil, errDoesNotCompile
}

func ModuleSpecs(ctx context.Context, db *sql.DB, minImportedByCount int) (specs []scan.ModuleSpec, err error) {
	return nil, errDoesNotCompile
}
