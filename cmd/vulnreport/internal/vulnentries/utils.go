// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulnentries

// This file is a subset of golang.org/x/vuln/internal/vulncheck/utils.go.

import (
	"context"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"

	"golang.org/x/tools/go/ssa"
)

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
// If a receiver is a pointer, this information is not encoded in the resulting name. The
// name of anonymous functions is simply "". The function names are unique subject to the
// enclosing package, but not globally.
//
// Examples:
//
//	func (a A) foo (...) {...}  -> A.foo
//	func foo(...) {...}         -> foo
//	func (b *B) bar (...) {...} -> B.bar
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
		return f.Name()
	}
	return qprefix + "." + f.Name()
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
