// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
)

// moduleRoots returns paths in repoRoot that are roots
// of a Go module. Each such discovered path is indexed
// with the name of the corresponding module. Each returned
// path has repoRoot as prefix.
func moduleRoots(repoRoot string) (map[string]string, error) {
	mods := make(map[string]string)
	err := filepath.Walk(repoRoot, func(path string, fi fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return nil
		}
		if filepath.Base(path) == "testdata" {
			return filepath.SkipDir
		}

		if modName, err := moduleName(path); err != nil {
			return err
		} else if modName != "" {
			mods[modName] = path
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mods, nil
}

// moduleName returns the name of the module if path is
// the root of a Go module. Otherwise, returns empty string.
func moduleName(path string) (string, error) {
	gomodPath := filepath.Join(path, "go.mod")
	data, err := os.ReadFile(gomodPath)
	if err != nil {
		// go.mod does not exist, so this is not an error.
		// It is just that the current path is not the root
		// of a Go module.
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	gomod, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return "", err
	}
	return gomod.Module.Mod.Path, nil
}
