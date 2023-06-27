// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"fmt"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
)

// Validate checks that the databases in newPath and oldPath are
// both valid databases, and that the database in newPath can
// be safely deployed on top of the database in oldPath.
func Validate(newPath, oldPath string) (err error) {
	derrors.Wrap(&err, "Validate(new=%s, old=%s)", newPath, oldPath)

	new, err := Load(newPath)
	if err != nil {
		return err
	}

	old, err := Load(oldPath)
	if err != nil {
		return err
	}

	return validate(new, old)
}

// validate checks for deleted files and inconsistent timestamps.
func validate(new, old *Database) error {
	newEntriesByID := make(map[string]osv.Entry, len(new.Entries))
	for _, newEntry := range new.Entries {
		newEntriesByID[newEntry.ID] = newEntry
	}
	for _, oldEntry := range old.Entries {
		newEntry, ok := newEntriesByID[oldEntry.ID]
		if !ok {
			return fmt.Errorf("%s is not present in new database. Use the %q field to delete an entry", oldEntry.ID, "withdrawn")
		}
		if newEntry.Published != oldEntry.Published {
			return fmt.Errorf("%s: published time cannot change (new %s, old %s)", oldEntry.ID, newEntry.Published, oldEntry.Published)
		}
		if newEntry.Modified.Before(oldEntry.Modified.Time) {
			return fmt.Errorf("%s: modified time cannot decrease (new %s, old %s)", oldEntry.ID, newEntry.Modified, oldEntry.Modified)
		}
	}
	return nil
}
