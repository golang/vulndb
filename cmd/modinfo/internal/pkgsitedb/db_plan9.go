// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build plan9

package pkgsitedb

import (
	"context"
	"database/sql"
	"errors"
)

var errDoesNotCompile = errors.New("github.com/lib/pq does not compile on plan9")

type Config struct {
	User           string
	PasswordSecret string
	Password       string
	Host           string
	Port           string
	DBName         string
}

func Open(ctx context.Context, cfg Config) (_ *sql.DB, err error) {
	return nil, errDoesNotCompile
}

type Module struct {
	Path     string
	Packages []*Package
}

type Package struct {
	Path         string
	Version      string
	NumImporters int
}

func QueryModule(ctx context.Context, db *sql.DB, modulePath string) (*Module, error) {
	return nil, errDoesNotCompile
}
