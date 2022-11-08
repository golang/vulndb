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
		IDsByAlias: make(map[string][]string),
	}

	if err := unmarshalFromFile(filepath.Join(dbPath, indexFile), &d.Index); err != nil {
		return nil, err
	}

	d.EntriesByModule, err = getEntriesByModule(dbPath, d.Index)
	if err != nil {
		return nil, err
	}

	d.EntriesByID, err = getEntriesByID(dbPath)
	if err != nil {
		return nil, err
	}

	if err := unmarshalFromFile(filepath.Join(dbPath, aliasesFile), &d.IDsByAlias); err != nil {
		return nil, err
	}

	return d, nil
}

func getEntriesByID(dbPath string) (map[string]*osv.Entry, error) {
	var ids []string
	if err := unmarshalFromFile(filepath.Join(dbPath, idDirectory, indexFile), &ids); err != nil {
		return nil, err
	}

	entriesByID := make(map[string]*osv.Entry, len(ids))
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

func getEntriesByModule(dbPath string, index client.DBIndex) (map[string][]*osv.Entry, error) {
	entriesByModule := make(map[string][]*osv.Entry, len(index))
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
