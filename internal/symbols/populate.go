// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package symbols

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/report"
)

// Populate attempts to populate the report with symbols derived
// from the patch link(s) in the report.
func Populate(r *report.Report) error {
	return populate(r, Patched)
}

func populate(r *report.Report, patched func(string, string, string) (map[string][]string, error)) error {
	var errs []error
	for _, mod := range r.Modules {
		hasFixLink := len(mod.FixLinks) >= 0
		fixLinks := mod.FixLinks
		if len(fixLinks) == 0 {
			c := r.CommitLinks()
			if len(c) == 0 {
				errs = append(errs, fmt.Errorf("no commit fix links found for module %s", mod.Module))
				continue
			}
			fixLinks = c
		}

		foundSymbols := false
		for _, fixLink := range fixLinks {
			found, err := populateFromFixLink(fixLink, mod, patched)
			if err != nil {
				errs = append(errs, err)
			}
			foundSymbols = foundSymbols || found
		}
		if !foundSymbols && fixLinks != nil {
			errs = append(errs, fmt.Errorf("no vulnerable symbols found for module %s", mod.Module))
		}
		// Sort fix links for testing/deterministic output
		if !hasFixLink {
			slices.Sort(mod.FixLinks)
		}
	}

	return errors.Join(errs...)
}

// populateFromFixLink takes a fixLink and a module and returns true if any symbols
// are found for the given fix/module pair.
func populateFromFixLink(fixLink string, m *report.Module, patched func(string, string, string) (map[string][]string, error)) (foundSymbols bool, err error) {
	fixHash := filepath.Base(fixLink)
	fixRepo := strings.TrimSuffix(fixLink, "/commit/"+fixHash)
	pkgsToSymbols, err := patched(m.Module, fixRepo, fixHash)
	if err != nil {
		return false, err
	}
	modPkgs := m.AllPackages()
	for pkg, symbols := range pkgsToSymbols {
		foundSymbols = true
		if modPkg, exists := modPkgs[pkg]; exists {
			// Ensure there are no duplicate symbols
			for _, s := range symbols {
				if !slices.Contains(modPkg.Symbols, s) {
					modPkg.Symbols = append(modPkg.Symbols, s)
				}
			}
		} else {
			m.Packages = append(m.Packages, &report.Package{
				Package: pkg,
				Symbols: symbols,
			})
		}
	}
	if foundSymbols {
		m.FixLinks = append(m.FixLinks, fixLink)
	}
	return foundSymbols, nil
}
