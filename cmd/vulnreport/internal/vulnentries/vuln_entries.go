// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulnentries

import (
	"context"
	"fmt"
	"go/token"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/vulndb/internal/report"
)

// Functions returns entries of pkgs call graph that lead to
// vulnerable symbols in m.
//
// It assumes that the modules in m present in pkgs, if any,
// are at a version deemed vulnerable by m.
func Functions(pkgs []*packages.Package, m *report.Module) ([]*ssa.Function, error) {
	ctx := context.Background()

	// The following code block is copied from
	// golang.org/x/vuln/internal/vulncheck/source.go:Source.
	var fset *token.FileSet
	for _, p := range pkgs {
		if fset == nil {
			fset = p.Fset
		} else {
			if fset != p.Fset {
				return nil, fmt.Errorf("[]*Package must have created with the same FileSet")
			}
		}
	}
	prog, ssaPkgs := buildSSA(pkgs, fset)
	entries := entryPoints(ssaPkgs)
	cg, err := callGraph(ctx, prog, entries)
	if err != nil {
		return nil, err
	}

	// Identify vulnerable functions/methods in the call graph and
	// compute the backwards reachable entries.
	entryNodes := vulnReachingEntries(cg, vulnFuncs(cg, m), entries)
	var vres []*ssa.Function
	for _, n := range entryNodes {
		vres = append(vres, n.Func)
	}
	return vres, nil
}

// vulnFuncs returns functions/methods of cg deemed vulnerable by m.
//
// It mimics golang.org/x/vuln/internal/vulncheck/source.go:vulnFuncs.
func vulnFuncs(cg *callgraph.Graph, m *report.Module) []*callgraph.Node {
	// Create a set of vulnerable symbols easy to query.
	type vulnSym struct {
		pkg string
		sym string
	}
	vulnSyms := make(map[vulnSym]bool)
	for _, p := range m.Packages {
		for _, s := range p.Symbols {
			vulnSyms[vulnSym{p.Package, s}] = true
		}
		for _, s := range p.DerivedSymbols { // for sanity
			vulnSyms[vulnSym{p.Package, s}] = true
		}
	}

	var vfs []*callgraph.Node
	for f, n := range cg.Nodes {
		if vulnSyms[vulnSym{pkgPath(f), dbFuncName(f)}] {
			vfs = append(vfs, n)
		}
	}
	return vfs
}

// vulnReachingEntries returns call graph nodes of cg corresponding to allEntries
// that are backwards reachable from sinks.
func vulnReachingEntries(cg *callgraph.Graph, sinks []*callgraph.Node, allEntries []*ssa.Function) []*callgraph.Node {
	allEs := make(map[*ssa.Function]bool)
	for _, e := range allEntries {
		allEs[e] = true
	}

	var vres []*callgraph.Node
	// The following code block mimics the body of
	// golang.org/x/vuln/internal/vulncheck/source.go:callGraphSlice.
	visited := make(map[*callgraph.Node]bool)
	var visit func(*callgraph.Node)
	visit = func(n *callgraph.Node) {
		if visited[n] {
			return
		}
		visited[n] = true

		if allEs[n.Func] {
			vres = append(vres, n)
		}

		for _, edge := range n.In {
			visit(edge.Caller)
		}
	}

	for _, s := range sinks {
		visit(s)
	}
	return vres
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
