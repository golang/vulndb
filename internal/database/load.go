// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vulndb/internal/derrors"
)

func Load(dbPath string) (_ client.DBIndex, _ map[string][]osv.Entry, err error) {
	defer derrors.Wrap(&err, "Load(%q)", dbPath)
	index := client.DBIndex{}
	dbMap := map[string][]osv.Entry{}

	var loadDir func(string) error
	loadDir = func(path string) error {
		dir, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, f := range dir {
			fpath := filepath.Join(path, f.Name())
			if f.IsDir() {
				if err := loadDir(fpath); err != nil {
					return err
				}
				continue
			}
			content, err := os.ReadFile(fpath)
			if err != nil {
				return err
			}
			if path == dbPath && f.Name() == "index.json" {
				if err := json.Unmarshal(content, &index); err != nil {
					return fmt.Errorf("unable to parse %q: %s", fpath, err)
				}
			} else if path == filepath.Join(dbPath, idDirectory) {
				if f.Name() == "index.json" {
					// The ID index is just a list of the entries' IDs; we'll
					// catch any diffs in the entries themselves.
					continue
				}
				var entry osv.Entry
				if err := json.Unmarshal(content, &entry); err != nil {
					return fmt.Errorf("unable to parse %q: %s", fpath, err)
				}
				fname := strings.TrimPrefix(fpath, dbPath)
				dbMap[fname] = []osv.Entry{entry}
			} else {
				var entries []osv.Entry
				if err := json.Unmarshal(content, &entries); err != nil {
					return fmt.Errorf("unable to parse %q: %s", fpath, err)
				}
				module := strings.TrimPrefix(fpath, dbPath)
				dbMap[module] = entries
			}
		}
		return nil
	}
	if err := loadDir(dbPath); err != nil {
		return nil, nil, err
	}
	return index, dbMap, nil
}
