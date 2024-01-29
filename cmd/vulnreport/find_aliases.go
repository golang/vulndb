// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/report"
)

// addMissingAliases uses the existing aliases in a report to find
// any missing aliases, and adds them to the report.
func addMissingAliases(ctx context.Context, r *report.Report, gc *ghsa.Client) (added int) {
	all := allAliases(ctx, r.Aliases(), gc)
	// If we have manually marked an identifier as "related", but
	// not actually an alias, don't override this decision.
	if len(r.Related) > 0 {
		all = removeRelated(all, r.Related)
	}
	return r.AddAliases(all)
}

func removeRelated(all, related []string) []string {
	// This is an uncommon operation, operating on short string slices,
	// so it doesn't need to be optimized.
	return slices.DeleteFunc(all, func(s string) bool {
		return slices.Contains(related, s)
	})
}

// allAliases returns a list of all aliases associated with the given knownAliases,
// (including the knownAliases themselves).
func allAliases(ctx context.Context, knownAliases []string, gc *ghsa.Client) []string {
	aliasesFor := func(ctx context.Context, alias string) ([]string, error) {
		switch {
		case ghsa.IsGHSA(alias):
			return aliasesForGHSA(ctx, alias, gc)
		case cveschema5.IsCVE(alias):
			return aliasesForCVE(ctx, alias, gc)
		default:
			return nil, fmt.Errorf("unsupported alias %s", alias)
		}
	}
	return aliasesBFS(ctx, knownAliases, aliasesFor)
}

func aliasesBFS(ctx context.Context, knownAliases []string,
	aliasesFor func(ctx context.Context, alias string) ([]string, error)) (all []string) {
	var queue []string
	var seen = make(map[string]bool)
	queue = append(queue, knownAliases...)

	for len(queue) > 0 {
		alias := queue[0]
		queue = queue[1:]

		if seen[alias] {
			continue
		}

		seen[alias] = true
		all = append(all, alias)
		aliases, err := aliasesFor(ctx, alias)
		if err != nil {
			log.Err(err)
			continue
		}
		queue = append(queue, aliases...)
	}

	slices.Sort(all)
	return slices.Compact(all)
}

func aliasesForGHSA(ctx context.Context, alias string, gc *ghsa.Client) (aliases []string, err error) {
	sa, err := gc.FetchGHSA(ctx, alias)
	if err != nil {
		return nil, fmt.Errorf("could not fetch GHSA record for %s", alias)
	}
	for _, id := range sa.Identifiers {
		if id.Type == "CVE" || id.Type == "GHSA" {
			aliases = append(aliases, id.Value)
		}
	}
	return aliases, nil
}

func aliasesForCVE(ctx context.Context, cve string, gc *ghsa.Client) (aliases []string, err error) {
	sas, err := gc.ListForCVE(ctx, cve)
	if err != nil {
		return nil, fmt.Errorf("could not find GHSAs for CVE %s", cve)
	}
	for _, sa := range sas {
		aliases = append(aliases, sa.ID)
	}
	return aliases, nil
}

// pickBestAlias returns the "best" alias in the list.
// By default, it prefers the first GHSA in the list, followed by the first CVE in the list
// (if no GHSA is present).
// If "preferCVE" is true, it prefers CVEs instead.
// If no GHSAs or CVEs are present, it returns ("", false).
func pickBestAlias(aliases []string, preferCVE bool) (_ string, ok bool) {
	firstChoice := ghsa.IsGHSA
	secondChoice := cveschema5.IsCVE
	if preferCVE {
		firstChoice, secondChoice = secondChoice, firstChoice
	}
	for _, alias := range aliases {
		if firstChoice(alias) {
			return alias, true
		}
	}
	for _, alias := range aliases {
		if secondChoice(alias) {
			return alias, true
		}
	}
	return "", false
}
