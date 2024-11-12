// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"fmt"

	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
)

// New creates a new database from the given entries.
// Errors if there are multiple entries with the same ID.
func New(entries ...osv.Entry) (*Database, error) {
	db := &Database{
		DB:      DBMeta{},
		Modules: make(ModulesIndex),
		Vulns:   make(VulnsIndex),
		Entries: make([]osv.Entry, 0, len(entries)),
	}
	for _, entry := range entries {
		if err := db.Add(entry); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// Add adds new entries to a database, erroring if any of the entries
// is already in the database.
func (db *Database) Add(entries ...osv.Entry) error {
	for _, entry := range entries {
		if err := db.Vulns.add(entry); err != nil {
			return err
		}
		// Only add the entry once we are sure it won't
		// cause an error.
		db.Entries = append(db.Entries, entry)
		db.Modules.add(entry)
		db.DB.add(entry)
	}
	return nil
}

func (dbi *DBMeta) add(entry osv.Entry) {
	if entry.Modified.After(dbi.Modified.Time) {
		dbi.Modified = entry.Modified
	}
}

func (m *ModulesIndex) add(entry osv.Entry) {
	for _, affected := range entry.Affected {
		modulePath := affected.Module.Path
		if _, ok := (*m)[modulePath]; !ok {
			(*m)[modulePath] = &Module{
				Path:  modulePath,
				Vulns: []ModuleVuln{},
			}
		}
		module := (*m)[modulePath]
		module.Vulns = append(module.Vulns, ModuleVuln{
			ID:       entry.ID,
			Modified: entry.Modified,
			Fixed:    osvutils.LatestFixed(affected.Ranges),
		})
	}
}

func (v *VulnsIndex) add(entry osv.Entry) error {
	if _, ok := (*v)[entry.ID]; ok {
		return fmt.Errorf("id %q appears twice in database", entry.ID)
	}
	(*v)[entry.ID] = &Vuln{
		ID:       entry.ID,
		Modified: entry.Modified,
		Aliases:  entry.Aliases,
	}
	return nil
}
