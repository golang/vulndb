// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestModuleFiles(t *testing.T) {
	fileNames := func(filePaths []string) []string {
		var fs []string
		for _, p := range filePaths {
			fs = append(fs, filepath.Base(p))
		}
		sort.Strings(fs)
		return fs
	}

	for _, tc := range []struct {
		module string
		want   []string
	}{
		{"golang.org/module", []string{"bar.go", "foo.go", "main.go"}},
		{"golang.org/nestedmodule", []string{"main_linux.go", "main_windows.go"}},
		{"golang.org/testdata", nil},
		{"golang.org/nonexistentmodule", nil},
	} {
		fPaths, err := moduleFiles("testdata/module", tc.module)
		if err != nil {
			t.Error(err)
		}
		got := fileNames(fPaths)
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("got %s; want %s", got, tc.want)
		}
	}
}

func TestModuleRoots(t *testing.T) {
	want := map[string]string{
		"golang.org/module":       "testdata/module",
		"golang.org/nestedmodule": "testdata/module/submodule",
	}
	got, err := moduleRoots("testdata/module")
	if err != nil {
		t.Fatal(err)
	}
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
			got = append(got, symbolName(fn))
		}
	}
	sort.Strings(got)
	want := []string{"A.Do", "B.Do", "Foo"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-got, want+):\n%s", diff)
	}
}
