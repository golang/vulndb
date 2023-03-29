// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

// FromRepo creates a new Database based on the contents of the "data/osv"
// folder in the given repo.
//
// It reads each OSV file, marshals it into a struct, updates the
// modified and published times based on the time of latest and first
// CL to modify the file, and stores the struct in the Database).
//
// The result is an in-memory vulnerability database
// that can be written to files via Database.Write.
//
// The repo must contain a "data/osv" folder with files in
// OSV JSON format with filenames of the form GO-YYYY-XXXX.json.
//
// Does not modify the repo.
func FromRepo(ctx context.Context, repo *git.Repository) (_ *Database, err error) {
	defer derrors.Wrap(&err, "FromRepo()")

	d, err := New()
	if err != nil {
		return nil, err
	}

	root, err := gitrepo.Root(repo)
	if err != nil {
		return nil, err
	}

	commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.HeadReference, report.OSVDir)
	if err != nil {
		return nil, err
	}

	if err = root.Files().ForEach(func(f *object.File) error {
		if filepath.Dir(f.Name) != report.OSVDir ||
			filepath.Ext(f.Name) != ".json" {
			return nil
		}

		// Read the entry.
		contents, err := f.Contents()
		if err != nil {
			return fmt.Errorf("could not read contents of file %s: %v", f.Name, err)
		}
		var entry osv.Entry
		err = json.Unmarshal([]byte(contents), &entry)
		if err != nil {
			return err
		}

		// Set the modified and published times.
		dates, ok := commitDates[f.Name]
		if !ok {
			return fmt.Errorf("can't find git repo commit dates for %q", f.Name)
		}
		addTimestamps(&entry, dates)

		d.Add(entry)

		return nil
	}); err != nil {
		return nil, err
	}

	return d, nil
}

func addTimestamps(entry *osv.Entry, dates gitrepo.Dates) {
	// If a report contains a published field, consider it
	// the authoritative source of truth.
	// Otherwise, use the time of the earliest commit in the git history.
	if entry.Published.IsZero() {
		entry.Published = osv.Time{Time: dates.Oldest}
	}

	// The modified time is the time of the latest commit for the file.
	entry.Modified = osv.Time{Time: dates.Newest}
}
