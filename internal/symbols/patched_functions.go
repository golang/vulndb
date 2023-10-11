// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// moduleFiles returns all .go files for a module within
// repo at repoRoot. Test Go files (*_test.go) and Go files
// in "testdata" subdirectories are omitted.
//
// If there are no Go files or module does not exist in the
// repo, empty file slice is returned. Each returned file
// path has repoRoot as its prefix.
func moduleFiles(repoRoot, module string) ([]string, error) {
	modRoots, err := moduleRoots(repoRoot)
	if err != nil {
		return nil, err
	}
	moduleRoot, ok := modRoots[module]
	if !ok {
		return nil, nil
	}

	// directlyUnder checks if path belongs
	// to module and not some of its sub-modules.
	directlyUnder := func(path string) bool {
		maxModPath := ""
		for _, modPath := range modRoots {
			if subdir(path, modPath) && len(modPath) > len(maxModPath) {
				maxModPath = modPath
			}
		}
		return maxModPath == moduleRoot
	}

	var files []string
	err = filepath.Walk(moduleRoot, func(path string, fi fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if filepath.Base(path) == "testdata" {
				// Skip test harness Go files.
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			// We are only interested in Go files.
			return nil
		}

		if !strings.HasSuffix(path, "_test.go") && directlyUnder(path) {
			// Skip test Go files and files that belong to sub-modules.
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, err
}

// subdir checks if target is a sub-directory of base. It assumes
// that both target and base are either absolute paths or relative
// paths with the same offset.
func subdir(target, base string) bool {
	p, err := filepath.Rel(base, target)
	return err == nil && !strings.Contains(p, "..")
}

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
