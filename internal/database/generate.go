// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
)

func Generate(ctx context.Context, repoDir, jsonDir string, indent bool) (err error) {
	defer derrors.Wrap(&err, "Generate(%q)", repoDir)

	jsonVulns, entries, err := generateEntries(ctx, repoDir)
	if err != nil {
		return err
	}

	index := make(client.DBIndex, len(jsonVulns))
	for modulePath, vulns := range jsonVulns {
		epath, err := client.EscapeModulePath(modulePath)
		if err != nil {
			return err
		}
		if err := writeVulns(filepath.Join(jsonDir, epath), vulns, indent); err != nil {
			return err
		}
		for _, v := range vulns {
			if v.Modified.After(index[modulePath]) {
				index[modulePath] = v.Modified
			}
		}
	}
	if err := WriteJSON(filepath.Join(jsonDir, "index.json"), index, indent); err != nil {
		return err
	}
	if err := writeAliasIndex(jsonDir, entries, indent); err != nil {
		return err
	}
	return writeEntriesByID(filepath.Join(jsonDir, idDirectory), entries, indent)
}

func generateEntries(ctx context.Context, repoDir string) (map[string][]osv.Entry, []osv.Entry, error) {
	repo, err := gitrepo.Open(ctx, repoDir)
	if err != nil {
		return nil, nil, err
	}

	osvFiles, err := os.ReadDir(filepath.Join(repoDir, osvDir))
	if err != nil {
		return nil, nil, fmt.Errorf("can't read %q: %s", osvDir, err)
	}

	commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.HeadReference, osvDir)
	if err != nil {
		return nil, nil, err
	}

	jsonVulns := map[string][]osv.Entry{}
	var entries []osv.Entry
	for _, f := range osvFiles {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		filename := filepath.Join(repoDir, osvDir, f.Name())
		entry, err := ReadOSV(filename)
		if err != nil {
			return nil, nil, err
		}
		dates, ok := commitDates[filename]
		if !ok {
			return nil, nil, fmt.Errorf("can't find git repo commit dates for %q", filename)
		}
		// If a report contains a published field, consider it
		// the authoritative source of truth. Otherwise, set
		// the published field from the git history.
		if entry.Published.IsZero() {
			entry.Published = dates.Oldest
		}
		entry.Modified = dates.Newest
		for _, modulePath := range ModulesForEntry(entry) {
			jsonVulns[modulePath] = append(jsonVulns[modulePath], entry)
		}
		entries = append(entries, entry)
	}
	return jsonVulns, entries, nil
}

func writeVulns(outPath string, vulns []osv.Entry, indent bool) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", filepath.Dir(outPath), err)
	}
	return WriteJSON(outPath+".json", vulns, indent)
}

func writeEntriesByID(idDir string, entries []osv.Entry, indent bool) error {
	// Write a directory containing entries by ID.
	if err := os.MkdirAll(idDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %v", idDir, err)
	}
	var idIndex []string
	for _, e := range entries {
		outPath := filepath.Join(idDir, e.ID+".json")
		if err := WriteJSON(outPath, e, indent); err != nil {
			return err
		}
		idIndex = append(idIndex, e.ID)
	}
	// Write an index.json in the ID directory with a list of all the IDs.
	return WriteJSON(filepath.Join(idDir, "index.json"), idIndex, indent)
}

// Write a JSON file containing a map from alias to GO IDs.
func writeAliasIndex(dir string, entries []osv.Entry, indent bool) error {
	aliasToGoIDs := map[string][]string{}
	for _, e := range entries {
		for _, a := range e.Aliases {
			aliasToGoIDs[a] = append(aliasToGoIDs[a], e.ID)
		}
	}
	return WriteJSON(filepath.Join(dir, "aliases.json"), aliasToGoIDs, indent)
}

func WriteJSON(filename string, value any, indent bool) (err error) {
	defer derrors.Wrap(&err, "writeJSON(%s)", filename)

	j, err := jsonMarshal(value, indent)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, j, 0644)
}

func jsonMarshal(v any, indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}
