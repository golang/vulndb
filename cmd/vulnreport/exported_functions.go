// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
	vdbclient "golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/report"
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
	entry, modules := database.GenerateOSVEntry("?", "?", time.Time{}, *r)
	for _, m := range modules {
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
