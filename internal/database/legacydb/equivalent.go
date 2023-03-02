// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package legacydb

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	db "golang.org/x/vulndb/internal/database"
)

// Equivalent returns an error if the v1 database in path does not
// represent the same data as the legacy database in legacyPath,
// or if either database is internally inconsistent according to its
// schema.
func Equivalent(path, legacyPath string) error {
	legacy, err := Load(legacyPath)
	if err != nil {
		return err
	}

	v1, err := db.Load(path)
	if err != nil {
		return err
	}

	// Since Load already checks each DB for internal consistency,
	// it is sufficient to check that each DB contains the same
	// vulnerabilities (OSV entries) and modules.
	return legacy.checkSameModulesAndVulns(v1)
}

func (legacy *Database) checkSameModulesAndVulns(v1 *db.Database) error {
	// Check that all the OSV entries are the same.
	if v0, v1 := len(legacy.EntriesByID), len(v1.Vulns); v0 != v1 {
		return fmt.Errorf("legacy database (num=%d) and v1 database (num=%d) have a different number of vulns", v0, v1)
	}
	for _, entry := range v1.Entries {
		legacyEntry, ok := legacy.EntriesByID[entry.ID]
		if !ok {
			return fmt.Errorf("v1 database contains vuln %q not present in legacy database", entry.ID)
		}
		if diff := cmp.Diff(legacyEntry, &entry); diff != "" {
			return fmt.Errorf("databases contain a different entry for id %s:\n%s", entry.ID, diff)
		}
	}

	// Check that all the module paths are the same.
	// This is technically not necessary if the validation in Load works
	// correctly, but we are double-checking because search-by-module
	// is such a common use case.
	if m0, m1 := len(legacy.Index), len(v1.Modules); m0 != m1 {
		return fmt.Errorf("legacy database (num=%d) and v1 database (num=%d) have a different number of modules", m0, m1)
	}
	for modulePath := range v1.Modules {
		_, ok := legacy.EntriesByModule[modulePath]
		if !ok {
			return fmt.Errorf("v1 database contains module %q not present in legacy database", modulePath)
		}
	}

	return nil
}
