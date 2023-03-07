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
	if err := db.writeIndex(filepath.Join(dir, indexDir), false); err != nil {
		return err
	}
	return db.writeEntries(filepath.Join(dir, idDir), false)
}

func (db *Database) writeIndex(dir string, gzip bool) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}

	if err := write(filepath.Join(dir, dbEndpoint), db.DB, gzip); err != nil {
		return err
	}

	if err := write(filepath.Join(dir, modulesEndpoint), db.Modules, gzip); err != nil {
		return err
	}

	return write(filepath.Join(dir, vulnsEndpoint), db.Vulns, gzip)
}

func (db *Database) writeEntries(dir string, gzip bool) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}

	for _, entry := range db.Entries {
		if err := write(filepath.Join(dir, entry.ID+".json"), entry, gzip); err != nil {
			return err
		}
	}
	return nil
}

func write(filename string, v any, gzip bool) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	// Write standard.
	if err := os.WriteFile(filename, b, 0644); err != nil {
		return err
	}

	if gzip {
		return writeGzipped(filename+".gz", b)
	}

	return nil
}
