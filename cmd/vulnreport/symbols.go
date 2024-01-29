// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

func findSymbols(_ context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "findSymbols(%q)", filename)
	infolog.Printf("symbols %s\n", filename)

	r, err := report.Read(filename)
	if err != nil {
		return err
	}
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

	for _, mod := range r.Modules {
		hasFixLink := mod.FixLink != ""
		if hasFixLink {
			defaultFixes = append(defaultFixes, mod.FixLink)
		}
		numFixedSymbols := make([]int, len(defaultFixes))
		for i, fixLink := range defaultFixes {
			fixHash := filepath.Base(fixLink)
			fixRepo := strings.TrimSuffix(fixLink, "/commit/"+fixHash)
			pkgsToSymbols, err := symbols.Patched(mod.Module, fixRepo, fixHash, errlog)
			if err != nil {
				errlog.Print(err)
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
	return r.Write(filename)
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
