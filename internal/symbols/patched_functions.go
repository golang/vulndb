// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package symbols

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/mod/modfile"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
)

// Patched returns symbols of module patched in commit identified
// by commitHash. repoURL is URL of the git repository containing
// the module.
//
// Patched returns a map from package import paths to symbols
// patched in the package. Test packages and symbols are omitted.
//
// If the commit has more than one parent, an error is returned.
func Patched(module, repoURL, commitHash string, errf logf) (_ map[string][]string, err error) {
	defer derrors.Wrap(&err, "Patched(%s, %s, %s)", module, repoURL, commitHash)

	repoRoot, err := os.MkdirTemp("", commitHash)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.RemoveAll(repoRoot)
	}()

	ctx := context.Background()
	repo, err := gitrepo.PlainClone(ctx, repoRoot, repoURL)
	if err != nil {
		return nil, err
	}

	w, err := repo.Worktree()
	if err != nil {
		return nil, err
	}

	hash := plumbing.NewHash(commitHash)
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, err
	}

	if commit.NumParents() != 1 {
		return nil, fmt.Errorf("more than 1 parent: %d", commit.NumParents())
	}

	parent, err := commit.Parent(0)
	if err != nil {
		return nil, err
	}

	if err := w.Checkout(&git.CheckoutOptions{Hash: hash, Force: true}); err != nil {
		return nil, err
	}

	newSymbols, err := moduleSymbols(repoRoot, module)
	if err != nil {
		return nil, err
	}

	if err := w.Checkout(&git.CheckoutOptions{Hash: parent.Hash, Force: true}); err != nil {
		return nil, err
	}

	oldSymbols, err := moduleSymbols(repoRoot, module)
	if err != nil {
		return nil, err
	}

	patched := patchedSymbols(oldSymbols, newSymbols, errf)
	pkgSyms := make(map[string][]string)
	for _, sym := range patched {
		pkgSyms[sym.pkg] = append(pkgSyms[sym.pkg], sym.symbol)
	}
	return pkgSyms, nil
}

// patchedSymbols returns symbol indices in oldSymbols that either 1) cannot
// be identified in newSymbols or 2) the corresponding functions have their
// source code changed.
func patchedSymbols(oldSymbols, newSymbols map[symKey]*ast.FuncDecl, errf logf) []symKey {
	var syms []symKey
	for key, of := range oldSymbols {
		nf, ok := newSymbols[key]
		if !ok {
			// We cannot locate the symbol in the new version
			// of code, so we designate it as being patched.
			syms = append(syms, key)
			continue
		}

		if source(of, errf) != source(nf, errf) {
			syms = append(syms, key)
		}
	}
	return syms
}

// source returns f's source code as text.
func source(f *ast.FuncDecl, errf logf) string {
	var b bytes.Buffer
	fs := token.NewFileSet()
	if err := printer.Fprint(&b, fs, f); err != nil {
		// should not happen, so just printing a warning
		errf("getting source of %s failed with %v", astSymbolName(f), err)
		return ""
	}
	return strings.TrimSpace(b.String())
}

// moduleSymbols indexes all symbols of a module located
// within repo at repoRoot. Test symbols are omitted.
//
// If the module is not defined in the repo, an empty
// index is returned.
func moduleSymbols(repoRoot, module string) (map[symKey]*ast.FuncDecl, error) {
	modRoot, files, err := moduleRootAndFiles(repoRoot, module)
	if err != nil {
		return nil, err
	}

	m := make(map[symKey]*ast.FuncDecl)
	fset := token.NewFileSet()
	for _, file := range files {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			return nil, err
		}

		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				m[symKey{
					pkg:    packageImportPath(module, modRoot, file),
					file:   filepath.Base(file),
					symbol: astSymbolName(fn)}] = fn
			}
		}
	}
	// Remove file info from indices that don't actually need it.
	// This should make things more robust for cases when there
	// the function name is unique and the patch moves the function
	// to a different file (due to, say, refactoring).
	return cleanFileInfo(m), nil
}

// cleanFileInfo deletes the value of file field in symKeys for
// function declarations that do not need the file information to
// differentiate between other same-named symbols in the same package.
func cleanFileInfo(syms map[symKey]*ast.FuncDecl) map[symKey]*ast.FuncDecl {
	// collisions tracks which symbols have multiple
	// function declarations in a package.
	collisions := make(map[symKey]int)
	for sk := range syms {
		k := symKey{pkg: sk.pkg, symbol: sk.symbol}
		collisions[k]++
	}

	m := make(map[symKey]*ast.FuncDecl)
	for sk, f := range syms {
		k := symKey{pkg: sk.pkg, symbol: sk.symbol}
		if collisions[k] > 1 {
			// multiple functions with the same name,
			// so we keep the file info.
			m[sk] = f
		} else {
			m[k] = f // get rid of file info
		}
	}
	return m
}

// symKey is used as a unique key for
// a Go symbol in a repo.
type symKey struct {
	pkg string
	// file is the name of the file where the symbol
	// is defined. Set when multiple same-named
	// symbols are hidden under different build tags.
	file   string
	symbol string
}

// moduleRootAndFiles returns the root of Go module within
// repo and all of its .go files. Test Go files (*_test.go)
// and Go files in "testdata" subdirectories are omitted.
//
// If there are no Go files or module does not exist in the
// repo, empty file slice is returned. Each returned file
// path has repoRoot as its prefix.
func moduleRootAndFiles(repoRoot, module string) (string, []string, error) {
	modRoots, err := moduleRoots(repoRoot)
	if err != nil {
		return "", nil, err
	}
	moduleRoot, ok := modRoots[module]
	if !ok {
		return "", nil, nil
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
		return "", nil, err
	}
	return moduleRoot, files, err
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

// astSymbolName returns the name of f as a symbol in
// a vulnerability database.
func astSymbolName(f *ast.FuncDecl) string {
	name := f.Name.Name
	if f.Recv == nil || len(f.Recv.List) == 0 {
		return name
	}
	field := f.Recv.List[0]
	if len(field.Names) == 0 {
		return "" // sanity
	}

	// unpackIdent assumes e is of the form id or id[...]
	// and then returns id. Otherwise, returns "".
	unpackIdent := func(e ast.Expr) string {
		switch xv := e.(type) {
		case *ast.Ident:
			return xv.Name
		case *ast.IndexExpr:
			if si, ok := xv.X.(*ast.Ident); ok {
				return si.Name
			}
		}
		return ""
	}

	// supported receiver type snames are id, *id, id[...], and *id[...].
	t := ""
	switch xv := field.Type.(type) {
	case *ast.StarExpr:
		t = unpackIdent(xv.X)
	case *ast.Ident, *ast.IndexExpr:
		t = unpackIdent(xv)
	default:
		panic(fmt.Sprintf("astSymbolName: unexpected receiver type: %v\n", reflect.TypeOf(field.Type)))
	}
	return t + "." + name
}
