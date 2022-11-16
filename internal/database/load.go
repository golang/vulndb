// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"path/filepath"

	"golang.org/x/exp/maps"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vulndb/internal/derrors"
)

// Load reads the contents of dbPath into a Database, and errors
// if the database has missing files (based on the module and ID indexes).
func Load(dbPath string) (_ *Database, err error) {
	defer derrors.Wrap(&err, "Load(%q)", dbPath)

	d := &Database{
		Index:      make(client.DBIndex),
		IDsByAlias: make(IDsByAlias),
	}

	if err := unmarshalFromFile(filepath.Join(dbPath, indexFile), &d.Index); err != nil {
		return nil, err
	}

	d.EntriesByModule, err = loadEntriesByModule(dbPath, d.Index)
	if err != nil {
		return nil, err
	}

	d.EntriesByID, err = loadEntriesByID(dbPath)
	if err != nil {
		return nil, err
	}

	if err := unmarshalFromFile(filepath.Join(dbPath, aliasesFile), &d.IDsByAlias); err != nil {
		return nil, err
	}

	return d, nil
}

func loadEntriesByID(dbPath string) (EntriesByID, error) {
	var ids []string
	if err := unmarshalFromFile(filepath.Join(dbPath, idDirectory, indexFile), &ids); err != nil {
		return nil, err
	}

	entriesByID := make(EntriesByID, len(ids))
	for _, id := range ids {
		var entry osv.Entry
		err := unmarshalFromFile(filepath.Join(dbPath, idDirectory, id+".json"), &entry)
		if err != nil {
			return nil, err
		}
		entriesByID[id] = &entry
	}
	return entriesByID, nil
}

func loadEntriesByModule(dbPath string, index client.DBIndex) (EntriesByModule, error) {
	entriesByModule := make(EntriesByModule, len(index))
	for _, module := range maps.Keys(index) {
		emodule, err := client.EscapeModulePath(module)
		if err != nil {
			return nil, err
		}
		fpath := filepath.Join(dbPath, emodule+".json")
		var entries []*osv.Entry
		err = unmarshalFromFile(fpath, &entries)
		if err != nil {
			return nil, err
		}
		entriesByModule[module] = entries
	}
	return entriesByModule, nil
}
