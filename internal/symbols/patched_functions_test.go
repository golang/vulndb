// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package symbols

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPatchedSymbols(t *testing.T) {
	toMap := func(syms []symKey) map[symKey]bool {
		m := make(map[symKey]bool)
		for _, s := range syms {
			m[s] = true
		}
		return m
	}

	for _, tc := range []struct {
		module        string
		oldRepoRoot   string
		fixedRepoRoot string
		want          map[symKey]bool
	}{
		{"golang.org/module", "testdata/module", "testdata/fixed-module", map[symKey]bool{
			{pkg: "golang.org/module", symbol: "Foo"}:          true,
			{pkg: "golang.org/module/internal", symbol: "Bar"}: true,
		}},
		{"golang.org/nestedmodule", "testdata/module", "testdata/fixed-module", map[symKey]bool{
			{pkg: "golang.org/nestedmodule", file: "main_linux.go", symbol: "main"}: true,
		}},
	} {
		oldSyms, err := moduleSymbols(tc.oldRepoRoot, tc.module)
		if err != nil {
			t.Error(err)
		}
		newSyms, err := moduleSymbols(tc.fixedRepoRoot, tc.module)
		if err != nil {
			t.Error(err)
		}

		got := toMap(patchedSymbols(oldSyms, newSyms, log.New(os.Stderr, "ERROR: ", 0)))
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("(-got, want+):\n%s", diff)
		}
	}
}

func TestModuleSymbols(t *testing.T) {
	symKeys := func(syms map[symKey]*ast.FuncDecl) map[symKey]bool {
		m := make(map[symKey]bool)
		for sym := range syms {
			m[sym] = true
		}
		return m
	}

	for _, tc := range []struct {
		module   string
		repoRoot string
		want     map[symKey]bool
	}{
		{"golang.org/module", "testdata/module", map[symKey]bool{
			{"golang.org/module", "", "Foo"}:          true,
			{"golang.org/module", "", "main"}:         true,
			{"golang.org/module/internal", "", "Bar"}: true,
		}},
		{"golang.org/nestedmodule", "testdata/module/submodule", map[symKey]bool{
			{"golang.org/nestedmodule", "main_linux.go", "main"}:   true,
			{"golang.org/nestedmodule", "main_windows.go", "main"}: true,
		}},
	} {
		syms, err := moduleSymbols(tc.repoRoot, tc.module)
		if err != nil {
			t.Error(err)
		}
		got := symKeys(syms)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("(-got, want+):\n%s", diff)
		}
	}
}

func TestModuleRootAndFiles(t *testing.T) {
	dirName := func(path string) string {
		if path == "" {
			return ""
		}
		rel, err := filepath.Rel("testdata", path)
		if err != nil {
			t.Error(err)
		}
		return filepath.ToSlash(rel)
	}

	fileNames := func(filePaths []string) []string {
		var fs []string
		for _, p := range filePaths {
			fs = append(fs, filepath.Base(p))
		}
		sort.Strings(fs)
		return fs
	}

	for _, tc := range []struct {
		module    string
		wantRoot  string
		wantFiles []string
	}{
		{"golang.org/module", "module", []string{"bar.go", "foo.go", "main.go"}},
		{"golang.org/nestedmodule", "module/submodule", []string{"main_linux.go", "main_windows.go"}},
		{"golang.org/testdata", "", nil},
		{"golang.org/nonexistentmodule", "", nil},
	} {
		modRoot, fPaths, err := moduleRootAndFiles("testdata/module", tc.module)
		if err != nil {
			t.Error(err)
		}

		gotFiles := fileNames(fPaths)
		if diff := cmp.Diff(tc.wantFiles, gotFiles); diff != "" {
			t.Errorf("got %s; want %s", gotFiles, tc.wantFiles)
		}

		gotRoot := dirName(modRoot)
		if gotRoot != tc.wantRoot {
			t.Errorf("module root: got %s; want %s", gotRoot, tc.wantRoot)
		}
	}
}

func TestModuleRoots(t *testing.T) {
	toSlash := func(modRoots map[string]string) map[string]string {
		m := make(map[string]string)
		for mod, root := range modRoots {
			m[mod] = filepath.ToSlash(root)
		}
		return m
	}

	want := map[string]string{
		"golang.org/module":       "testdata/module",
		"golang.org/nestedmodule": "testdata/module/submodule",
	}
	roots, err := moduleRoots("testdata/module")
	if err != nil {
		t.Fatal(err)
	}
	got := toSlash(roots)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-got, want+):\n%s", diff)
	}
}

func TestPackageImportPath(t *testing.T) {
	const module = "golang.org/module"
	for _, tc := range []struct {
		root string
		path string
		want string
	}{
		// relative paths
		{"modroot", "modroot/main.go", "golang.org/module"},
		{"modroot", "modroot/", "golang.org/module"},
		{"./modroot", "./modroot/main.go", "golang.org/module"},
		{"modroot", "modroot/internal/internal.go", "golang.org/module/internal"},
		{"modroot", "modroot/internal/", "golang.org/module/internal"},
		{"modroot", "modroot/exp/foo/foo.go", "golang.org/module/exp/foo"},
		// absolute paths
		{"/modroot", "/modroot/exp/foo/foo.go", "golang.org/module/exp/foo"},
		{"/", "/internal/internal.go", "golang.org/module/internal"},
		{"/", "/internal/", "golang.org/module/internal"},
	} {
		got := packageImportPath(module, tc.root, tc.path)
		if got != tc.want {
			t.Errorf("got %s; want %s", got, tc.want)
		}
	}
}

func TestSymbolName(t *testing.T) {
	src := `
package p

func Foo() {}

type A struct {}
func (a A) Do() {}

type B struct {}
func (b *B) Do() {}
`
	fset := token.NewFileSet() // positions are relative to fset
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		t.Error(err)
	}

	var got []string
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			got = append(got, astSymbolName(fn))
		}
	}
	sort.Strings(got)
	want := []string{"A.Do", "B.Do", "Foo"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-got, want+):\n%s", diff)
	}
}
