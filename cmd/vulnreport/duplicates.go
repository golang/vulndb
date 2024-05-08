// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/vulndb/cmd/vulnreport/log"
)

type duplicates struct {
	// protects aliasesToIssues
	mu              sync.Mutex
	aliasesToIssues map[string][]int

	*aliasFinder
	*xrefer
	*issueParser
}

func (*duplicates) name() string { return "duplicates" }

func (*duplicates) usage() (string, string) {
	const desc = "finds likely duplicates of the given Github issue (with no args, looks at all open issues)"
	return "<no args> | " + ghIssueArgs, desc
}

func (*duplicates) close() error {
	return nil
}

func (d *duplicates) setup(ctx context.Context) error {
	d.aliasesToIssues = make(map[string][]int)

	d.issueParser = new(issueParser)
	d.xrefer = new(xrefer)
	return setupAll(ctx, d.xrefer, d.issueParser)
}

func (d *duplicates) run(ctx context.Context, issNum string) (err error) {
	iss, err := d.lookup(ctx, issNum)
	if err != nil {
		return err
	}

	if d.skip(iss, d.skipReason) {
		return nil
	}

	aliases := aliases(iss)

	if len(aliases) == 0 {
		log.Infof("skipping issue #%d (no aliases found)", iss.Number)
		return nil
	}

	aliases = d.allAliases(ctx, aliases)
	var allXrefs []string
	for _, a := range aliases {
		var xrefs []string

		// Find existing reports with this alias.
		if reports := d.rc.ReportsByAlias(a); len(reports) != 0 {
			for _, r := range reports {
				fname, err := r.YAMLFilename()
				if err != nil {
					fname = r.ID
				}
				xrefs = append(xrefs, fname)
			}
		}

		// Find other open issues with this alias.
		if issNums, ok := d.aliasesToIssues[a]; ok {
			for _, in := range issNums {
				xrefs = append(xrefs, d.ic.Reference(in))
			}
		}

		d.addAlias(a, iss.Number)

		if len(xrefs) != 0 {
			allXrefs = append(allXrefs, fmt.Sprintf("#%d shares alias %s with %s", iss.Number, a, strings.Join(xrefs, ", ")))
		}
	}

	if len(allXrefs) != 0 {
		log.Outf("%s is a likely duplicate:\n - %s", d.ic.Reference(iss.Number), strings.Join(allXrefs, "\n - "))
	} else {
		log.Infof("found no existing reports or open issues with aliases in issue #%d", iss.Number)
	}
	return nil
}

func (d *duplicates) addAlias(a string, n int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.aliasesToIssues[a] = append(d.aliasesToIssues[a], n)
}
