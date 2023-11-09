// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/report"
)

// Load loads a database assuming that path contains a full, valid
// database following the v1 specification.
//
// It errors if:
//   - any required files are missing or invalid
//   - any unexpected files are found in the index/ or ID/ folders
//     (with the exception that ID/index.json, from the legacy spec, is ignored)
//
// Any files present in the top level directory are ignored.
func Load(path string) (_ *Database, err error) {
	defer derrors.Wrap(&err, "Load(%q)", path)

	db, err := RawLoad(filepath.Join(path, idDir))
	if err != nil {
		return nil, err
	}

	requireGzip := true
	if err := db.validateIndex(filepath.Join(path, indexDir), requireGzip); err != nil {
		return nil, err
	}
	if err := db.validateEntries(filepath.Join(path, idDir), requireGzip); err != nil {
		return nil, err
	}
	return db, nil
}

// RawLoad loads a database assuming that vulnsPath contains ".json" files
// representing OSV entries.
// It errors if any of the files cannot be unmarshaled into osv.Entry.
// It does not require any database indexes or gzipped files to be present,
// Directories and non-JSON files are ignored.
// Also, to accommodate the legacy spec, the file "index.json" is ignored
// if present.
func RawLoad(vulnsPath string) (_ *Database, err error) {
	defer derrors.Wrap(&err, "RawLoad(%q)", vulnsPath)

	db, err := New()
	if err != nil {
		return nil, err
	}

	if err := filepath.WalkDir(vulnsPath, func(path string, f fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fname := f.Name()
		if f.IsDir() ||
			fname == "index.json" ||
			filepath.Ext(fname) != ".json" {
			return nil
		}
		var entry osv.Entry
		if err = report.UnmarshalFromFile(path, &entry); err != nil {
			return fmt.Errorf("could not unmarshal %q: %v", path, err)
		}
		return db.Add(entry)
	}); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *Database) validateIndex(indexPath string, requireGzip bool) (err error) {
	defer derrors.Wrap(&err, "validateIndex(%q)", indexPath)

	// Check that the index files are present and have the correct
	// contents.
	dbPath := filepath.Join(indexPath, dbEndpoint)
	if err := checkFiles(dbPath, db.DB, requireGzip); err != nil {
		return err
	}
	modulesPath := filepath.Join(indexPath, modulesEndpoint)
	if err := checkFiles(modulesPath, db.Modules, requireGzip); err != nil {
		return err
	}
	vulnsPath := filepath.Join(indexPath, vulnsEndpoint)
	if err := checkFiles(vulnsPath, db.Vulns, requireGzip); err != nil {
		return err
	}

	// Check for unexpected files in the index folder.
	expected := []string{
		indexDir,
		dbEndpoint, dbEndpoint + ".gz",
		modulesEndpoint, modulesEndpoint + ".gz",
		vulnsEndpoint, vulnsEndpoint + ".gz",
	}
	return checkNoUnexpectedFiles(indexPath, expected)
}

func (db *Database) validateEntries(idPath string, requireGzip bool) (err error) {
	defer derrors.Wrap(&err, "validateEntries(%q)", idPath)

	expected := []string{
		idDir,
		"index.json", // index.json is OK to accommodate legacy spec
	}
	for _, entry := range db.Entries {
		if err = osvutils.Validate(&entry); err != nil {
			return err
		}
		path := filepath.Join(idPath, entry.ID+".json")
		if err = checkFiles(path, entry, requireGzip); err != nil {
			return err
		}
		expected = append(expected, entry.ID+".json", entry.ID+".json.gz")
	}

	return checkNoUnexpectedFiles(idPath, expected)
}

func checkNoUnexpectedFiles(path string, expected []string) error {
	if err := filepath.WalkDir(path, func(path string, f fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !slices.Contains(expected, f.Name()) {
			return fmt.Errorf("unexpected file %s", f.Name())
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// checkFiles ensures that filepath and filepath+".gz" exist and
// have contents consistent with v.
// Returns an error if:
//   - any expected files don't exist or v cannot be marshaled
//   - the contents of filepath do not match the result
//     of marshaling v
//   - the uncompressed contents of filepath+".gz" do not match the
//     contents of filepath
func checkFiles(filepath string, v any, requireGzip bool) (err error) {
	defer derrors.Wrap(&err, "checkFiles(%q)", filepath)

	contents, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}
	marshaled, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if c, m := string(contents), string(marshaled); c != m {
		return fmt.Errorf("%s: contents do not match marshaled bytes of value:\ncontents:\n%s\nvalue (marshaled):\n%s", filepath, c, m)
	}

	if requireGzip {
		gzipped, err := readGzipped(filepath + ".gz")
		if err != nil {
			return err
		}
		if c, g := string(contents), string(gzipped); c != g {
			return fmt.Errorf("%[1]s: contents of uncompressed file do not match contents of compressed file:\ncontents of %[1]s:\n%[2]s\ncontents of %[1]s.gz:\n%[3]s", filepath, c, g)
		}
	}

	return nil
}
