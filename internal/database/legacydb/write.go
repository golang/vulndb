// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package legacydb

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/mod/module"
	db "golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
)

// Write writes the contents of the Database to JSON files,
// following the legacy specification in
// https://go.dev/security/vuln/database#api.
// path is the base path where the database will be written, and indent
// indicates if the JSON should be indented.
func (d *Database) Write(path string, indent bool) (err error) {
	defer derrors.Wrap(&err, "Database.Write(%q)", path)

	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", path, err)
	}

	if err = d.writeIndex(path, indent); err != nil {
		return err
	}

	if err = d.writeAliasIndex(path, indent); err != nil {
		return err
	}

	if err = d.writeEntriesByModule(path, indent); err != nil {
		return err
	}

	if err = d.writeEntriesByID(path, indent); err != nil {
		return err
	}

	return nil
}

func (d *Database) writeIndex(path string, indent bool) error {
	return db.WriteJSON(filepath.Join(path, indexFile), d.Index, indent)
}

func (d *Database) writeAliasIndex(path string, indent bool) error {
	return db.WriteJSON(filepath.Join(path, aliasesFile), d.IDsByAlias, indent)
}

func (d *Database) writeEntriesByModule(path string, indent bool) error {
	for module, entries := range d.EntriesByModule {
		epath, err := escapeModulePath(module)
		if err != nil {
			return err
		}
		outPath := filepath.Join(path, epath)
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory %q: %s", filepath.Dir(outPath), err)
		}
		if err = db.WriteJSON(outPath+".json", entries, indent); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) writeEntriesByID(path string, indent bool) error {
	idDirPath := filepath.Join(path, idDirectory)
	if err := os.MkdirAll(idDirPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %v", idDirPath, err)
	}
	// Write the entry files.
	for _, entry := range d.EntriesByID {
		if err := db.WriteJSON(filepath.Join(idDirPath, entry.ID+".json"), entry, indent); err != nil {
			return err
		}
	}
	idIndex := maps.Keys(d.EntriesByID)
	slices.Sort(idIndex)
	// Write the ID Index.
	return db.WriteJSON(filepath.Join(idDirPath, indexFile), idIndex, indent)
}

// Pseudo-module paths used for parts of the Go system.
// These are technically not valid module paths, so we
// mustn't pass them to module.EscapePath.
// Keep in sync with vulndb/internal/database/generate.go.
var specialCaseModulePaths = map[string]bool{
	osv.GoStdModulePath: true,
	osv.GoCmdModulePath: true,
}

// escapeModulePath is like golang.org/x/mod/module.EscapePath,
// but accounts for special paths used by the vulnerability database.
func escapeModulePath(path string) (string, error) {
	if specialCaseModulePaths[path] {
		return path, nil
	}
	return module.EscapePath(path)
}

// unescapeModulePath is like golang.org/x/mod/module.UnescapePath, but
// accounts for special paths used by the vulnerability database.
func unescapeModulePath(path string) (string, error) {
	if specialCaseModulePaths[path] {
		return path, nil
	}
	return module.UnescapePath(path)
}
