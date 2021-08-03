// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/osv"
)

func loadDB(dbPath string) (osv.DBIndex, map[string][]osv.Entry, error) {
	index := osv.DBIndex{}
	dbMap := map[string][]osv.Entry{}

	var loadDir func(string) error
	loadDir = func(path string) error {
		dir, err := ioutil.ReadDir(path)
		if err != nil {
			return err
		}
		for _, f := range dir {
			fpath := filepath.Join(path, f.Name())
			if f.IsDir() {
				loadDir(fpath)
				continue
			}
			content, err := ioutil.ReadFile(fpath)
			if err != nil {
				return err
			}
			if path == dbPath && f.Name() == "index.json" {
				if err := json.Unmarshal(content, &index); err != nil {
					return fmt.Errorf("unable to parse %q: %s", fpath, err)
				}
			} else {
				var entries []osv.Entry
				if err := json.Unmarshal(content, &entries); err != nil {
					return fmt.Errorf("unable to parse %q: %s", fpath, err)
				}
				module := strings.TrimSuffix(strings.TrimPrefix(fpath, dbPath), filepath.Ext(fpath))
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

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: dbdiff db-a db-b")
		os.Exit(1)
	}
	indexA, dbA, err := loadDB(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load %q: %s\n", os.Args[1], err)
		os.Exit(1)
	}
	indexB, dbB, err := loadDB(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load %q: %s\n", os.Args[2], err)
		os.Exit(1)
	}
	indexDiff := cmp.Diff(indexA, indexB)
	if indexDiff == "" {
		indexDiff = "(no change)"
	}
	dbDiff := cmp.Diff(dbA, dbB)
	if dbDiff == "" {
		dbDiff = "(no change)"
	}
	fmt.Printf("# index\n%s\n\n# db\n%s\n", indexDiff, dbDiff)
}
