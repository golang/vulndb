// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package symbols

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

// Populate attempts to populate the report with symbols derived
// from the patch link(s) in the report.
func Populate(r *report.Report) error {
	return populate(r, Patched)
}

func populate(r *report.Report, patched func(string, string, string) (map[string][]string, error)) error {
	var defaultFixes []string

	for _, ref := range r.References {
		if ref.Type == osv.ReferenceTypeFix {
			if filepath.Base(filepath.Dir(ref.URL)) == "commit" {
				defaultFixes = append(defaultFixes, ref.URL)
			}
		}
	}
	if len(defaultFixes) == 0 {
		return fmt.Errorf("no commit fix links found")
	}
	var errs []error
	for _, mod := range r.Modules {
		hasFixLink := mod.FixLink != ""
		if hasFixLink {
			defaultFixes = append(defaultFixes, mod.FixLink)
		}
		numFixedSymbols := make([]int, len(defaultFixes))
		for i, fixLink := range defaultFixes {
			fixHash := filepath.Base(fixLink)
			fixRepo := strings.TrimSuffix(fixLink, "/commit/"+fixHash)
			pkgsToSymbols, err := patched(mod.Module, fixRepo, fixHash)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			packages := mod.AllPackages()
			for pkg, symbols := range pkgsToSymbols {
				if _, exists := packages[pkg]; exists {
					packages[pkg].Symbols = append(packages[pkg].Symbols, symbols...)
				} else {
					mod.Packages = append(mod.Packages, &report.Package{
						Package: pkg,
						Symbols: symbols,
					})
				}
				numFixedSymbols[i] += len(symbols)
			}
		}
		// if the module's link field wasn't already populated, populate it with
		// the link that results in the most symbols
		if hasFixLink {
			defaultFixes = defaultFixes[:len(defaultFixes)-1]
		} else {
			mod.FixLink = defaultFixes[indexMax(numFixedSymbols)]
		}
	}

	return errors.Join(errs...)
}

// indexMax takes a slice of nonempty ints and returns the index of the maximum value
func indexMax(s []int) (index int) {
	maxVal := s[0]
	index = 0
	for i, val := range s {
		if val > maxVal {
			maxVal = val
			index = i
		}
	}
	return index
}
