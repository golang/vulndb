// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package database provides functionality for generating, reading, writing,
// and validating vulnerability databases.
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
)

// Database is an in-memory representation of a Go vulnerability database,
// following the specification at https://go.dev/security/vuln/database#api.
type Database struct {
	// A map from module names to the last modified time.
	// Represents $dbPath/index.json
	Index client.DBIndex
	// Map from each Go ID to its OSV entry.
	// Represents $dbPath/ID/index.json and the contents of $dbPath/ID/
	EntriesByID EntriesByID
	// Map from each module path to a list of corresponding OSV entries.
	// Each map entry represents the contents of a $dbPath/$modulePath.json
	// file.
	EntriesByModule EntriesByModule
	// Map from each alias (CVE and GHSA) ID to a list of Go IDs for that
	// alias.
	// Represents $dbPath/aliases.json
	IDsByAlias IDsByAlias
}

type (
	EntriesByID     map[string]*osv.Entry
	EntriesByModule map[string][]*osv.Entry
	IDsByAlias      map[string][]string
)

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

func New(ctx context.Context, repo *git.Repository) (_ *Database, err error) {
	defer derrors.Wrap(&err, "New()")

	d := &Database{
		Index:           make(client.DBIndex),
		EntriesByID:     make(EntriesByID),
		EntriesByModule: make(EntriesByModule),
		IDsByAlias:      make(IDsByAlias),
	}

	root, err := gitrepo.Root(repo)
	if err != nil {
		return nil, err
	}

	commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.HeadReference, osvDir)
	if err != nil {
		return nil, err
	}

	if err = root.Files().ForEach(func(f *object.File) error {
		if filepath.Dir(f.Name) != osvDir ||
			filepath.Ext(f.Name) != ".json" {
			return nil
		}

		// Read the entry.
		contents, err := f.Contents()
		if err != nil {
			return fmt.Errorf("could not read contents of file %s: %v", f.Name, err)
		}
		var entry osv.Entry
		err = json.Unmarshal([]byte(contents), &entry)
		if err != nil {
			return err
		}

		// Set the modified and published times.
		dates, ok := commitDates[f.Name]
		if !ok {
			return fmt.Errorf("can't find git repo commit dates for %q", f.Name)
		}
		addTimestamps(&entry, dates)

		d.addEntry(&entry)

		return nil
	}); err != nil {
		return nil, err
	}

	return d, nil
}

func (d *Database) addEntry(entry *osv.Entry) {
	for _, module := range ModulesForEntry(*entry) {
		d.EntriesByModule[module] = append(d.EntriesByModule[module], entry)
		if entry.Modified.After(d.Index[module]) {
			d.Index[module] = entry.Modified
		}
	}
	d.EntriesByID[entry.ID] = entry
	for _, alias := range entry.Aliases {
		d.IDsByAlias[alias] = append(d.IDsByAlias[alias], entry.ID)
	}
}

func addTimestamps(entry *osv.Entry, dates gitrepo.Dates) {
	// If a report contains a published field, consider it
	// the authoritative source of truth.
	// Otherwise, use the time of the earliest commit in the git history.
	if entry.Published.IsZero() {
		entry.Published = dates.Oldest
	}

	// The modified time is the time of the latest commit for the file.
	entry.Modified = dates.Newest
}
