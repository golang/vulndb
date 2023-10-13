// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"go/ast"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
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

// packageImportPath computes the full package import path for a
// a package directory or file on local disk, given a module path
// and root of a module on local disk. For instance,
//
//	 packageImportPath("golang.org/module", "/module/root",
//		"module/root/internal/foo/foo.go") =
//				"golang.org/module/internal/foo"
//
// Returns empty string in case of any errors or if moduleRoot is
// not a sub-path of path.
//
// moduleRoot and path have to be either both absolute or both
// relative paths. The last element in path will always be interpreted
// as a file, hence directory paths should end with a file separator.
func packageImportPath(module, moduleRoot, pkgPath string) string {
	if !subdir(pkgPath, moduleRoot) {
		return ""
	}
	dir := filepath.Dir(pkgPath)
	rel, err := filepath.Rel(moduleRoot, dir)
	if err != nil {
		return ""
	}
	if rel == "." {
		// The path is moduleRoot
		return module
	}
	rel = filepath.ToSlash(rel) // cross platform
	return path.Join(module, rel)
}

// symbolName returns the name of f as a symbol in
// a vulnerability database.
func symbolName(f *ast.FuncDecl) string {
	name := f.Name.Name
	if f.Recv == nil || len(f.Recv.List) == 0 {
		return name
	}
	field := f.Recv.List[0]
	if len(field.Names) == 0 {
		return "" // sanity
	}

	t := ""
	switch xv := field.Type.(type) {
	case *ast.StarExpr:
		if si, ok := xv.X.(*ast.Ident); ok {
			t = si.Name
		}
	case *ast.Ident:
		t = xv.Name
	case *ast.IndexExpr:
		// TODO(#63535): cover index instructions stemming from generics
		return ""
	default:
		panic(fmt.Sprintf("symbolName: unexpected receiver type: %v\n", reflect.TypeOf(field.Type)))
	}
	return t + "." + name
}
