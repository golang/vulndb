// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/tools/go/packages"
	vdbclient "golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
	"golang.org/x/vulndb/internal/derrors"
	iosv "golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/stdlib"
)

// A reportClient is a vulndb.Client that returns the Entry for a single report.
type reportClient struct {
	vdbclient.Client
	entry           *osv.Entry
	entriesByModule map[string][]*osv.Entry
}

// newReportClient creates a reportClient from a given report.
func newReportClient(r *report.Report) *reportClient {
	entries := map[string][]*osv.Entry{}
	entry := generateOSVEntry(r)
	for _, m := range modulesForEntry(entry) {
		entries[m] = append(entries[m], &entry)
	}
	return &reportClient{entry: &entry, entriesByModule: entries}
}

// GetByModule implements vdbclient.Client.GetByModule.
func (e *reportClient) GetByModule(ctx context.Context, m string) ([]*osv.Entry, error) {
	return e.entriesByModule[m], nil
}

// exportedFunctions returns a set of vulnerable functions exported by a set of packages
// from the same module.
func exportedFunctions(pkgs []*packages.Package, rc *reportClient) (_ map[string]bool, err error) {
	defer derrors.Wrap(&err, "exportedFunctions(%q)", pkgs[0].PkgPath)

	if pkgs[0].Module != nil && !affected(rc.entry, pkgs[0].Module.Version) {
		fmt.Fprintf(os.Stderr, "version %s of module %s is not affected by this vuln\n",
			pkgs[0].Module.Version, pkgs[0].Module.Path)
		return map[string]bool{}, nil
	}
	vpkgs := vulncheck.Convert(pkgs)
	res, err := vulncheck.Source(context.Background(), vpkgs, &vulncheck.Config{Client: rc})
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
	for _, ei := range res.Calls.Entries {
		e := res.Calls.Functions[ei]
		if e.PkgPath == pkgs[0].PkgPath {
			names[symbolName(e)] = true
		}
	}
	return names, nil
}

func symbolName(fn *vulncheck.FuncNode) string {
	if fn.RecvType == "" {
		return fn.Name
	}
	// Remove package path from type.
	i := strings.LastIndexByte(fn.RecvType, '.')
	if i < 0 {
		return fn.RecvType + "." + fn.Name
	}
	return fn.RecvType[i+1:] + "." + fn.Name
}

func affected(e *osv.Entry, version string) bool {
	for _, a := range e.Affected {
		if a.Ranges.AffectsSemver(version) {
			return true
		}
	}
	return false
}

// generateOSV creates a new OSV entry in the x/vuln OSV format.
// The entry only contains an Affected field, because all other fields
// are irrelevant for finding derived symbols.
// Used temporarily in the transition away from x/vuln.
func generateOSVEntry(r *report.Report) osv.Entry {
	entry := osv.Entry{}

	for _, m := range r.Modules {
		name := m.Module
		switch name {
		case stdlib.ModulePath:
			name = iosv.GoStdModulePath
		case stdlib.ToolchainModulePath:
			name = iosv.GoCmdModulePath
		}
		imps := make([]osv.EcosystemSpecificImport, 0)
		for _, p := range m.Packages {
			syms := append([]string{}, p.Symbols...)
			syms = append(syms, p.DerivedSymbols...)
			sort.Strings(syms)
			imps = append(imps, osv.EcosystemSpecificImport{
				Path:    p.Package,
				GOOS:    p.GOOS,
				GOARCH:  p.GOARCH,
				Symbols: syms,
			})
		}
		a := osv.AffectsRange{Type: osv.TypeSemver}
		if len(m.Versions) == 0 || m.Versions[0].Introduced == "" {
			a.Events = append(a.Events, osv.RangeEvent{Introduced: "0"})
		}
		for _, v := range m.Versions {
			if v.Introduced != "" {
				a.Events = append(a.Events, osv.RangeEvent{Introduced: v.Introduced.Canonical()})
			}
			if v.Fixed != "" {
				a.Events = append(a.Events, osv.RangeEvent{Fixed: v.Fixed.Canonical()})
			}
		}
		entry.Affected = append(entry.Affected, osv.Affected{
			Package: osv.Package{
				Name:      name,
				Ecosystem: osv.GoEcosystem,
			},
			Ranges: []osv.AffectsRange{a},
			EcosystemSpecific: osv.EcosystemSpecific{
				Imports: imps,
			},
		})
	}
	return entry
}

func modulesForEntry(entry osv.Entry) []string {
	mods := map[string]bool{}
	for _, a := range entry.Affected {
		mods[a.Package.Name] = true
	}
	return maps.Keys(mods)
}
