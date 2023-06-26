// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package legacydb

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/vulndb/internal/osv"
)

var existingDir = filepath.FromSlash("testdata/db/existing")

func TestValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		// validDir contains a new entry and correct modified and
		// published timestamps with respect to existing.
		if err := Validate(validDir, existingDir); err != nil {
			t.Error(err)
		}
	})

	t.Run("old on new fails", func(t *testing.T) {
		// Attempting to deploy the existing database on top of the new
		// database should fail, as an entry is missing and timestamps are
		// incorrect.
		if err := Validate(existingDir, validDir); err == nil {
			t.Error("expected error, got nil")
		}
	})
}

func newTestDB(entries ...*osv.Entry) *Database {
	d := newEmpty()
	for _, entry := range entries {
		d.addEntry(entry)
	}
	return d
}

func TestValidateInternal(t *testing.T) {
	successTests := []struct {
		name  string
		newDB *Database
		oldDB *Database
	}{
		{
			name: "valid updates ok",
			oldDB: newTestDB(
				&osv.Entry{
					ID:        "GO-1999-0001",
					Published: jan1999,
					Modified:  jan1999,
				}),
			newDB: newTestDB(&osv.Entry{
				ID:        "GO-1999-0001",
				Published: jan1999,
				Modified:  jan2000,
			}, &osv.Entry{
				ID:        "GO-1999-0002",
				Published: jan2000,
				Modified:  jan2000,
			}),
		},
		{
			name:  "same db ok",
			oldDB: valid,
			newDB: valid,
		},
	}
	for _, test := range successTests {
		t.Run(test.name, func(t *testing.T) {
			if err := validate(test.newDB, test.oldDB); err != nil {
				t.Errorf("validate(): unexpected error %v", err)
			}
		})
	}

	failTests := []struct {
		name    string
		newDB   *Database
		oldDB   *Database
		wantErr string
	}{
		{
			name: "published time changed",
			oldDB: newTestDB(
				&osv.Entry{
					ID:        "GO-1999-0001",
					Published: jan1999,
					Modified:  jan1999,
				}),
			newDB: newTestDB(&osv.Entry{
				ID:        "GO-1999-0001",
				Published: jan2000,
				Modified:  jan2000,
			}),
			wantErr: "published time cannot change",
		},
		{
			name: "deleted entry",
			oldDB: newTestDB(
				&osv.Entry{
					ID:        "GO-1999-0001",
					Published: jan1999,
					Modified:  jan1999,
				}),
			newDB:   newTestDB(),
			wantErr: "GO-1999-0001 is not present in new database",
		},
		{
			name: "modified time decreased",
			oldDB: newTestDB(
				&osv.Entry{
					ID:       "GO-1999-0001",
					Modified: jan2000,
				}),
			newDB: newTestDB(&osv.Entry{
				ID:       "GO-1999-0001",
				Modified: jan1999,
			}),
			wantErr: "modified time cannot decrease",
		},
	}
	for _, test := range failTests {
		t.Run(test.name, func(t *testing.T) {
			if err := validate(test.newDB, test.oldDB); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("validate(): want error containing %q, got %v", test.wantErr, err)
			}
		})
	}
}
