// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"fmt"

	"golang.org/x/vulndb/internal/derrors"
)

// Validate checks that the databases in newPath and oldPath are
// both valid databases, and that the database in newPath can
// be safely deployed on top of the database in oldPath.
func Validate(newPath, oldPath string) (err error) {
	derrors.Wrap(&err, "Validate(new=%s, old=%s)", newPath, oldPath)

	// Load will fail if either of the databases is internally
	// inconsistent.
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
	for id, oldEntry := range old.EntriesByID {
		newEntry, ok := new.EntriesByID[id]
		if !ok {
			return fmt.Errorf("%s is not present in new database. Use the %q field to delete an entry", id, "withdrawn")
		}
		if newEntry.Published != oldEntry.Published {
			return fmt.Errorf("%s: published time cannot change (new %s, old %s)", id, newEntry.Published, oldEntry.Published)
		}
		if newEntry.Modified.Before(oldEntry.Modified) {
			return fmt.Errorf("%s: modified time cannot decrease (new %s, old %s)", id, newEntry.Modified, oldEntry.Modified)
		}
	}
	return nil
}
