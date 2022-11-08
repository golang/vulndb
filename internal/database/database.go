// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package database provides functionality for generating, reading, writing,
// and validating vulnerability databases.
package database

import (
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

// Database is an in-memory representation of a Go vulnerability database,
// following the specification at https://go.dev/security/vuln/database#api.
type Database struct {
	// A map from module names to the last modified time.
	// Represents $dbPath/index.json
	Index client.DBIndex
	// Map from each Go ID to its OSV entry.
	// Represents $dbPath/ID/index.json and the contents of $dbPath/ID/
	EntriesByID map[string]*osv.Entry
	// Map from each module path to a list of corresponding OSV entries.
	// Each map entry represents the contents of a $dbPath/$modulePath.json
	// file.
	EntriesByModule map[string][]*osv.Entry
	// Map from each alias (CVE and GHSA) ID to a list of Go IDs for that
	// alias.
	// Represents $dbPath/aliases.json
	IDsByAlias map[string][]string
}

const (
	// indexFile is the name of the file that contains the database
	// index.
	indexFile = "index.json"

	// aliasesFile is the name of the file that contains the database
	// aliases index.
	aliasesFile = "aliases.json"

	// idDirectory is the name of the directory that contains entries
	// listed by their IDs.
	idDirectory = "ID"

	// yamlDir is the name of the directory in the vulndb repo that
	// contains reports.
	yamlDir = "data/reports"

	// osvDir is the name of the directory in the vulndb repo that
	// contains reports.
	osvDir = "data/osv"

	// versionFile is the name of the file in the vulndb repo that
	// tracks the generator version.
	versionFile = "data/version.md"

	// stdFileName is the name of the .json file in the vulndb repo
	// that will contain info on standard library vulnerabilities.
	stdFileName = "stdlib"

	// toolchainFileName is the name of the .json file in the vulndb repo
	// that will contain info on toolchain (cmd/...) vulnerabilities.
	toolchainFileName = "toolchain"
)
