// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package legacydb

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	dbv1 "golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

// Load reads the contents of dbPath into a Database, and errors if:
//   - Any files are malformed (cannot be unmarshaled)
//   - The database has missing files (based on the module and ID indexes)
//   - The database has unexpected files not listed in the indexes
//   - The database is internally inconsistent
func Load(dbPath string) (_ *Database, err error) {
	defer derrors.Wrap(&err, "Load(%s)", dbPath)

	d, err := rawLoad(dbPath)
	if err != nil {
		return nil, err
	}
	if err := d.checkNoUnexpectedFiles(dbPath); err != nil {
		return nil, err
	}
	if err := d.checkInternalConsistency(); err != nil {
		return nil, err
	}

	return d, nil
}

// rawLoad reads the contents of dbPath into a Database, and errors
// if any files are malformed, or the database has missing files
// (based on the module and ID indexes).
func rawLoad(dbPath string) (_ *Database, err error) {
	defer derrors.Wrap(&err, "loading data")

	d := &Database{
		Index:      make(DBIndex),
		IDsByAlias: make(IDsByAlias),
	}

	if err := report.UnmarshalFromFile(filepath.Join(dbPath, indexFile), &d.Index); err != nil {
		return nil, fmt.Errorf("invalid or missing index.json: %v", err)
	}

	d.EntriesByModule, err = loadEntriesByModule(dbPath, d.Index)
	if err != nil {
		return nil, err
	}

	d.EntriesByID, err = loadEntriesByID(dbPath)
	if err != nil {
		return nil, err
	}

	if err := report.UnmarshalFromFile(filepath.Join(dbPath, aliasesFile), &d.IDsByAlias); err != nil {
		return nil, fmt.Errorf("invalid or missing aliases.json: %v", err)
	}

	return d, nil
}

func (d *Database) checkNoUnexpectedFiles(dbPath string) error {
	return filepath.WalkDir(dbPath, func(path string, f fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fname := f.Name()
		ext := filepath.Ext(fname)
		dir := filepath.Dir(path)

		switch {
		// Skip directories.
		case f.IsDir():
			return nil
		// Skip files in the v1 spec.
		case ext == ".gz" || ext == ".zip" || dbv1.IsIndexEndpoint(fname):
			return nil
		// In the top-level directory, web files and index files are OK.
		case dir == dbPath && isIndexOrWebFile(fname, ext):
			return nil
		// All non-directory and non-web files should end in ".json".
		case ext != ".json":
			return fmt.Errorf("found unexpected non-JSON file %s", path)
		// All files in the ID directory (except the index) should have
		// corresponding entries in EntriesByID.
		case dir == filepath.Join(dbPath, idDirectory):
			if fname == indexFile {
				return nil
			}
			id := report.GoID(fname)
			if _, ok := d.EntriesByID[id]; !ok {
				return fmt.Errorf("found unexpected file %q which is not present in %s", fname, filepath.Join(idDirectory, indexFile))
			}
		// All other files should have corresponding entries in
		// EntriesByModule.
		default:
			module := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(path, dbPath), string(filepath.Separator)), ".json")
			unescaped, err := unescapeModulePath(filepath.ToSlash(module))
			if err != nil {
				return fmt.Errorf("could not unescape module file %s: %v", path, err)
			}
			if _, ok := d.EntriesByModule[unescaped]; !ok {
				return fmt.Errorf("found unexpected module %q which is not present in %s", unescaped, indexFile)
			}
		}
		return nil
	})
}

func isIndexOrWebFile(filename, ext string) bool {
	return ext == ".ico" ||
		ext == ".html" ||
		// HTML files may have no extension.
		ext == "" ||
		filename == indexFile ||
		filename == aliasesFile
}

func (d *Database) checkInternalConsistency() error {
	if il, ml := len(d.Index), len(d.EntriesByModule); il != ml {
		return fmt.Errorf("length mismatch: there are %d module entries in the index, and %d module directory entries", il, ml)
	}

	for module, modified := range d.Index {
		entries, ok := d.EntriesByModule[module]
		if !ok || len(entries) == 0 {
			return fmt.Errorf("no module directory found for indexed module %s", module)
		}

		var wantModified osv.Time
		for _, entry := range entries {
			if mod := entry.Modified; mod.After(wantModified.Time) {
				wantModified = mod
			}

			entryByID, ok := d.EntriesByID[entry.ID]
			if !ok {
				return fmt.Errorf("no advisory found for ID %s listed in %s", entry.ID, module)
			}
			if !reflect.DeepEqual(entry, entryByID) {
				return fmt.Errorf("inconsistent OSV contents in module and ID advisory for %s", entry.ID)
			}

			var found bool
			for _, affected := range entry.Affected {
				m := affected.Module.Path
				if m == module {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s does not reference %s", entry.ID, module)
			}
		}
		if modified != wantModified.Time {
			return fmt.Errorf("incorrect modified timestamp for module %s: want %s, got %s", module, wantModified.Time, modified)
		}
	}

	for id, entry := range d.EntriesByID {
		for _, affected := range entry.Affected {
			module := affected.Module.Path
			entries, ok := d.EntriesByModule[module]
			if !ok || len(entries) == 0 {
				return fmt.Errorf("module %s not found (referenced by %s)", module, id)
			}
			found := false
			for _, gotEntry := range entries {
				if gotEntry.ID == id {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s does not have an entry in %s", id, module)
			}
		}
		for _, alias := range entry.Aliases {
			gotEntries, ok := d.IDsByAlias[alias]
			if !ok || len(gotEntries) == 0 {
				return fmt.Errorf("alias %s not found in aliases.json (alias of %s)", alias, id)
			}
			found := false
			for _, gotID := range gotEntries {
				if gotID == id {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s is not listed as an alias of %s in aliases.json", entry.ID, alias)
			}
		}
		if entry.Published.After(entry.Modified.Time) {
			return fmt.Errorf("%s: published time (%s) cannot be after modified time (%s)", entry.ID, entry.Published, entry.Modified)
		}
	}

	for alias, goIDs := range d.IDsByAlias {
		for _, goID := range goIDs {
			entry, ok := d.EntriesByID[goID]
			if !ok {
				return fmt.Errorf("no advisory found for %s listed under %s", goID, alias)
			}

			if !slices.Contains(entry.Aliases, alias) {
				return fmt.Errorf("advisory %s does not reference alias %s", goID, alias)
			}
		}
	}

	return nil
}
func loadEntriesByID(dbPath string) (EntriesByID, error) {
	var ids []string
	if err := report.UnmarshalFromFile(filepath.Join(dbPath, idDirectory, indexFile), &ids); err != nil {
		return nil, fmt.Errorf("invalid or missing ID/index.json: %v", err)
	}

	entriesByID := make(EntriesByID, len(ids))
	for _, id := range ids {
		var entry osv.Entry
		err := report.UnmarshalFromFile(filepath.Join(dbPath, idDirectory, id+".json"), &entry)
		if err != nil {
			return nil, fmt.Errorf("invalid or missing OSV file: %v", err)
		}
		entriesByID[id] = &entry
	}
	return entriesByID, nil
}

func loadEntriesByModule(dbPath string, index DBIndex) (EntriesByModule, error) {
	entriesByModule := make(EntriesByModule, len(index))
	for _, module := range maps.Keys(index) {
		emodule, err := escapeModulePath(module)
		if err != nil {
			return nil, err
		}
		fpath := filepath.Join(dbPath, emodule+".json")
		var entries []*osv.Entry
		err = report.UnmarshalFromFile(fpath, &entries)
		if err != nil {
			return nil, fmt.Errorf("invalid or missing module directory: %v", err)
		}
		entriesByModule[module] = entries
	}
	return entriesByModule, nil
}
