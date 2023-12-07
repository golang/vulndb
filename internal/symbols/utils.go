// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package symbols

// This file is a subset of golang.org/x/vuln/internal/vulncheck/utils.go.

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"go/token"
	"go/types"
	"os"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
	"golang.org/x/vulndb/internal/derrors"

	"golang.org/x/tools/go/ssa"
)

// loadPackage loads the package at the given import path, with enough
// information for constructing a call graph.
func loadPackage(cfg *packages.Config, importPath string) (_ *packages.Package, err error) {
	defer derrors.Wrap(&err, "loadPackage(%s)", importPath)

	cfg.Mode |= packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg.BuildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(build.Default.BuildTags, ","))}
	pkgs, err := packages.Load(cfg, importPath)
	if err != nil {
		return nil, err
	}

	if err := packageLoadingError(pkgs); err != nil {
		return nil, err
	}

	if len(pkgs) == 0 {
		return nil, errors.New("no packages found")
	}
	if len(pkgs) > 1 {
		return nil, fmt.Errorf("multiple (%d) packages found for import path %s", len(pkgs), importPath)
	}

	return pkgs[0], nil
}

// packageLoadingError returns an error summarizing packages.Package.Errors if there were any.
func packageLoadingError(pkgs []*packages.Package) error {
	pkgError := func(pkg *packages.Package) error {
		var msgs []string
		for _, err := range pkg.Errors {
			msgs = append(msgs, err.Error())
		}
		if len(msgs) == 0 {
			return nil
		}
		// Report a more helpful error message for the package if possible.
		for _, msg := range msgs {
			// cgo failure?
			if strings.Contains(msg, "could not import C (no metadata for C)") {
				const url = `https://github.com/golang/vulndb/blob/master/doc/triage.md#vulnreport-cgo-failures`
				return fmt.Errorf("package %s has a cgo error (install relevant C packages? %s)\nerrors:%s", pkg.PkgPath, url, strings.Join(msgs, "\n"))
			}
		}
		return fmt.Errorf("package %s had %d errors: %s", pkg.PkgPath, len(msgs), strings.Join(msgs, "\n"))
	}

	var paths []string
	var msgs []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if err := pkgError(pkg); err != nil {
			paths = append(paths, pkg.PkgPath)
			msgs = append(msgs, err.Error())
		}
	})
	if len(msgs) == 0 {
		return nil // no errors
	}
	return fmt.Errorf("packages with errors: %s\nerrors:\n%s", strings.Join(paths, " "), strings.Join(msgs, "\n"))
}

// buildSSA creates an ssa representation for pkgs. Returns
// the ssa program encapsulating the packages and top level
// ssa packages corresponding to pkgs.
func buildSSA(pkgs []*packages.Package, fset *token.FileSet) (*ssa.Program, []*ssa.Package) {
	// TODO(https://go.dev/issue/57221): what about entry functions that are generics?
	prog := ssa.NewProgram(fset, ssa.InstantiateGenerics)

	imports := make(map[*packages.Package]*ssa.Package)
	var createImports func(map[string]*packages.Package)
	createImports = func(pkgs map[string]*packages.Package) {
		for _, p := range pkgs {
			if _, ok := imports[p]; !ok {
				i := prog.CreatePackage(p.Types, p.Syntax, p.TypesInfo, true)
				imports[p] = i
				createImports(p.Imports)
			}
		}
	}

	for _, tp := range pkgs {
		createImports(tp.Imports)
	}

	var ssaPkgs []*ssa.Package
	for _, tp := range pkgs {
		if sp, ok := imports[tp]; ok {
			ssaPkgs = append(ssaPkgs, sp)
		} else {
			sp := prog.CreatePackage(tp.Types, tp.Syntax, tp.TypesInfo, false)
			ssaPkgs = append(ssaPkgs, sp)
		}
	}
	prog.Build()
	return prog, ssaPkgs
}

// callGraph builds a call graph of prog based on VTA analysis.
func callGraph(ctx context.Context, prog *ssa.Program, entries []*ssa.Function) (*callgraph.Graph, error) {
	entrySlice := make(map[*ssa.Function]bool)
	for _, e := range entries {
		entrySlice[e] = true
	}

	if err := ctx.Err(); err != nil { // cancelled?
		return nil, err
	}
	initial := cha.CallGraph(prog)
	allFuncs := ssautil.AllFunctions(prog)

	fslice := forwardSlice(entrySlice, initial)
	// Keep only actually linked functions.
	pruneSet(fslice, allFuncs)

	if err := ctx.Err(); err != nil { // cancelled?
		return nil, err
	}
	vtaCg := vta.CallGraph(fslice, initial)

	// Repeat the process once more, this time using
	// the produced VTA call graph as the base graph.
	fslice = forwardSlice(entrySlice, vtaCg)
	pruneSet(fslice, allFuncs)

	if err := ctx.Err(); err != nil { // cancelled?
		return nil, err
	}
	cg := vta.CallGraph(fslice, vtaCg)
	cg.DeleteSyntheticNodes()
	return cg, nil
}

// dbTypeFormat formats the name of t according how types
// are encoded in vulnerability database:
//   - pointer designation * is skipped
//   - full path prefix is skipped as well
func dbTypeFormat(t types.Type) string {
	switch tt := t.(type) {
	case *types.Pointer:
		return dbTypeFormat(tt.Elem())
	case *types.Named:
		return tt.Obj().Name()
	default:
		return types.TypeString(t, func(p *types.Package) string { return "" })
	}
}

// dbFuncName computes a function name consistent with the namings used in vulnerability
// databases. Effectively, a qualified name of a function local to its enclosing package.
// If a receiver is a pointer, this information is not encoded in the resulting name. If
// a function has type argument/parameter, this information is omitted. The name of
// anonymous functions is simply "". The function names are unique subject to the enclosing
// package, but not globally.
//
// Examples:
//
//	func (a A) foo (...) {...}  -> A.foo
//	func foo(...) {...}         -> foo
//	func (b *B) bar (...) {...} -> B.bar
//	func (c C[T]) do(...) {...} -> C.do
func dbFuncName(f *ssa.Function) string {
	selectBound := func(f *ssa.Function) types.Type {
		// If f is a "bound" function introduced by ssa for a given type, return the type.
		// When "f" is a "bound" function, it will have 1 free variable of that type within
		// the function. This is subject to change when ssa changes.
		if len(f.FreeVars) == 1 && strings.HasPrefix(f.Synthetic, "bound ") {
			return f.FreeVars[0].Type()
		}
		return nil
	}
	selectThunk := func(f *ssa.Function) types.Type {
		// If f is a "thunk" function introduced by ssa for a given type, return the type.
		// When "f" is a "thunk" function, the first parameter will have that type within
		// the function. This is subject to change when ssa changes.
		params := f.Signature.Params() // params.Len() == 1 then params != nil.
		if strings.HasPrefix(f.Synthetic, "thunk ") && params.Len() >= 1 {
			if first := params.At(0); first != nil {
				return first.Type()
			}
		}
		return nil
	}
	var qprefix string
	if recv := f.Signature.Recv(); recv != nil {
		qprefix = dbTypeFormat(recv.Type())
	} else if btype := selectBound(f); btype != nil {
		qprefix = dbTypeFormat(btype)
	} else if ttype := selectThunk(f); ttype != nil {
		qprefix = dbTypeFormat(ttype)
	}

	if qprefix == "" {
		return funcName(f)
	}
	return qprefix + "." + funcName(f)
}

// funcName returns the name of the ssa function f.
// It is f.Name() without additional type argument
// information in case of generics.
func funcName(f *ssa.Function) string {
	n, _, _ := strings.Cut(f.Name(), "[")
	return n
}

// memberFuncs returns functions associated with the `member`:
// 1) `member` itself if `member` is a function
// 2) `member` methods if `member` is a type
// 3) empty list otherwise
func memberFuncs(member ssa.Member, prog *ssa.Program) []*ssa.Function {
	switch t := member.(type) {
	case *ssa.Type:
		methods := typeutil.IntuitiveMethodSet(t.Type(), &prog.MethodSets)
		var funcs []*ssa.Function
		for _, m := range methods {
			if f := prog.MethodValue(m); f != nil {
				funcs = append(funcs, f)
			}
		}
		return funcs
	case *ssa.Function:
		return []*ssa.Function{t}
	default:
		return nil
	}
}

// pkgPath returns the path of the f's enclosing package, if any.
// Otherwise, returns "".
//
// Copy of golang.org/x/vuln/internal/vulncheck/source.go:pkgPath.
func pkgPath(f *ssa.Function) string {
	if f.Package() != nil && f.Package().Pkg != nil {
		return f.Package().Pkg.Path()
	}
	return ""
}

func changeToTempDir() (cleanup func(), _ error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vulnreport")
	if err != nil {
		return nil, err
	}
	cleanup = func() {
		_ = os.RemoveAll(dir)
		_ = os.Chdir(cwd)
	}
	if err := os.Chdir(dir); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, err
}
