// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package symbols

import (
	"bytes"
	"errors"
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/version"
)

// Exported returns a set of vulnerable symbols, in the vuln
// db format, exported by a package p from the module m.
func Exported(m *report.Module, p *report.Package) (_ []string, err error) {
	defer derrors.Wrap(&err, "Exported(%q, %q)", m.Module, p.Package)

	cleanup, err := changeToTempDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	run := func(name string, arg ...string) error {
		cmd := exec.Command(name, arg...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %v\nout:\n%s", name, err, string(out))
		}
		return nil
	}

	// This procedure was developed through trial and error finding a way
	// to load symbols for GO-2023-1549, which has a dependency tree that
	// includes go.mod files that reference v0.0.0 versions which do not exist.
	//
	// Create an empty go.mod.
	if err := run("go", "mod", "init", "go.dev/_"); err != nil {
		return nil, err
	}
	if !m.IsFirstParty() {
		// Require the module we're interested in at the vulnerable_at version.
		if err := run("go", "mod", "edit", "-require", m.Module+"@v"+m.VulnerableAt); err != nil {
			return nil, err
		}
		for _, req := range m.VulnerableAtRequires {
			if err := run("go", "mod", "edit", "-require", req); err != nil {
				return nil, err
			}
		}
		// TODO: This is the logical place to update the vulnerable module to locally
		// use a different version of a module when necessary for .
		// Example: data/reports/GO-2023-2399.yaml
		//   go mod edit -require github.com/hashicorp/vault@1.15.3
		// which requires
		//   go get github.com/hashicorp/vault/sdk@v0.10.2
		// to locally derive symbols.
		// It may potentially make sense to extend yaml report format with
		// these if this is a recurring problem.

		// Create a package that imports the package we're interested in.
		var content bytes.Buffer
		fmt.Fprintf(&content, "package p\n")
		fmt.Fprintf(&content, "import _ %q\n", p.Package)
		for _, req := range m.VulnerableAtRequires {
			pkg, _, _ := strings.Cut(req, "@")
			fmt.Fprintf(&content, "import _ %q", pkg)
		}
		if err := os.WriteFile("p.go", content.Bytes(), 0666); err != nil {
			return nil, err
		}
	}
	// Run go mod tidy.
	if err := run("go", "mod", "tidy"); err != nil {
		return nil, err
	}

	pkg, err := loadPackage(&packages.Config{}, p.Package)
	if err != nil {
		return nil, err
	}
	// First package should match package path and module.
	if pkg.PkgPath != p.Package {
		return nil, fmt.Errorf("first package had import path %s, wanted %s", pkg.PkgPath, p.Package)
	}
	if m.IsFirstParty() {
		if pm := pkg.Module; pm != nil {
			return nil, fmt.Errorf("got module %v, expected nil", pm)
		}
	} else {
		if pm := pkg.Module; pm == nil || pm.Path != m.Module {
			return nil, fmt.Errorf("got module %v, expected %s", pm, m.Module)
		}
	}

	if len(p.Symbols) == 0 {
		return nil, nil // no symbols to derive from. skip.
	}

	// Check to see that all symbols actually exist in the package.
	// This should perhaps be a lint check, but lint doesn't
	// load/typecheck packages at the moment, so do it here for now.
	if err := checkSymbols(pkg, p.Symbols); err != nil {
		return nil, fmt.Errorf("invalid symbol(s):\n%w", err)
	}

	newsyms, err := exportedFunctions(pkg, m)
	if err != nil {
		return nil, err
	}
	var newslice []string
	for s := range newsyms {
		if s == "init" {
			// Exclude init funcs from consideration.
			//
			// Assume that if init is calling a vulnerable symbol,
			// it is doing so in a safe fashion (for example, the
			// function might be vulnerable only when provided with
			// untrusted input).
			continue
		}
		if !slices.Contains(p.Symbols, s) {
			newslice = append(newslice, s)
		}
	}
	sort.Strings(newslice)
	return newslice, nil
}

func checkSymbols(pkg *packages.Package, symbols []string) error {
	var errs []error
	for _, sym := range symbols {
		if typ, method, ok := strings.Cut(sym, "."); ok {
			n, ok := pkg.Types.Scope().Lookup(typ).(*types.TypeName)
			if !ok {
				errs = append(errs, fmt.Errorf("%v: type not found", typ))
				continue
			}
			m, _, _ := types.LookupFieldOrMethod(n.Type(), true, pkg.Types, method)
			if m == nil {
				errs = append(errs, fmt.Errorf("%v: method not found", sym))
			}
		} else {
			_, ok := pkg.Types.Scope().Lookup(typ).(*types.Func)
			if !ok {
				errs = append(errs, fmt.Errorf("%v: func not found", typ))
			}
		}
	}
	return errors.Join(errs...)
}

// exportedFunctions returns a set of vulnerable functions exported
// by a packages from the module.
func exportedFunctions(pkg *packages.Package, m *report.Module) (_ map[string]bool, err error) {
	defer derrors.Wrap(&err, "exportedFunctions(%q)", pkg.PkgPath)

	if pkg.Module != nil {
		v := version.TrimPrefix(pkg.Module.Version)
		affected, err := osvutils.AffectsSemver(report.AffectedRanges(m.Versions), v)
		if err != nil {
			return nil, err
		}
		if !affected {
			return nil, fmt.Errorf("version %s of module %s is not affected by this vuln", v, pkg.Module.Path)
		}
	}

	entries, err := vulnEntries([]*packages.Package{pkg}, m)
	if err != nil {
		return nil, err
	}
	// Return the name of all entry points.
	// Note that "main" and "init" are both possible entries.
	// Both have clear meanings: "main" means that invoking
	// the program is a problem, and "init" means that very likely
	// some global state is altered, and so every exported function
	// is vulnerable. For now, we leave it to consumers to use this
	// information as they wish.
	names := map[string]bool{}
	for _, e := range entries {
		if pkgPath(e) == pkg.PkgPath {
			names[dbFuncName(e)] = true
		}
	}
	return names, nil
}
