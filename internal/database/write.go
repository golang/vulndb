// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (db *Database) Write(dir string) error {
	if err := db.WriteIndex(filepath.Join(dir, indexDir)); err != nil {
		return err
	}
	return db.WriteEntries(filepath.Join(dir, idDir))
}

func (db *Database) WriteIndex(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}

	if err := write(filepath.Join(dir, dbEndpoint), db.DB); err != nil {
		return err
	}

	if err := write(filepath.Join(dir, modulesEndpoint), db.Modules); err != nil {
		return err
	}

	return write(filepath.Join(dir, vulnsEndpoint), db.Vulns)
}

func (db *Database) WriteEntries(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}

	for _, entry := range db.Entries {
		if err := write(filepath.Join(dir, entry.ID+".json"), entry); err != nil {
			return err
		}
	}
	return nil
}

func write(filename string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	// Write standard.
	if err := os.WriteFile(filename, b, 0644); err != nil {
		return err
	}

	return writeGzipped(filename+".gz", b)
}
