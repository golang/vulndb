// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/genericosv"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/report"
)

type aliasFinder struct {
	gc *ghsa.Client
}

func (af *aliasFinder) setup(ctx context.Context) error {
	if *githubToken == "" {
		return fmt.Errorf("githubToken must be provided")
	}
	af.gc = ghsa.NewClient(ctx, *githubToken)
	return nil
}

// addMissingAliases uses the existing aliases in a report to find
// any missing aliases, and adds them to the report.
func (r *yamlReport) addMissingAliases(ctx context.Context, af *aliasFinder) (added int) {
	all := af.allAliases(ctx, r.Aliases())
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
func (a *aliasFinder) allAliases(ctx context.Context, knownAliases []string) []string {
	aliasesFor := func(ctx context.Context, alias string) ([]string, error) {
		switch {
		case idstr.IsGHSA(alias):
			return aliasesForGHSA(ctx, alias, a.gc)
		case idstr.IsCVE(alias):
			return aliasesForCVE(ctx, alias, a.gc)
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
		return nil, fmt.Errorf("aliasesForGHSA(%s): could not fetch GHSA record from GraphQL API", alias)
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
		return nil, fmt.Errorf("aliasesForCVE(%s): could not find GHSAs from GraphQL API", cve)
	}
	for _, sa := range sas {
		aliases = append(aliases, sa.ID)
	}
	return aliases, nil
}

// sourceFromBestAlias returns a report source fetched from the "best" alias in the list.
// By default, it prefers the first GHSA in the list, followed by the first CVE in the list
// (if no GHSA is present).
// If "preferCVE" is true, it prefers CVEs instead.
func (af *aliasFinder) sourceFromBestAlias(ctx context.Context, aliases []string, preferCVE bool) (report.Source, bool) {
	firstChoice := idstr.IsGHSA
	secondChoice := idstr.IsCVE
	if preferCVE {
		firstChoice, secondChoice = secondChoice, firstChoice
	}

	find := func(f func(string) bool) (report.Source, bool) {
		for _, alias := range aliases {
			if f(alias) {
				src, err := af.fetch(ctx, alias)
				if err != nil {
					continue
				}
				return src, true
			}
		}
		return nil, false
	}

	if src, found := find(firstChoice); found {
		return src, true
	}

	if src, found := find(secondChoice); found {
		return src, true
	}

	return report.Original(), false
}

func (a *aliasFinder) fetch(ctx context.Context, alias string) (report.Source, error) {
	var f report.Fetcher
	switch {
	case idstr.IsGHSA(alias):
		if *graphQL {
			f = a.gc
		} else {
			f = genericosv.NewFetcher()
		}
	case idstr.IsCVE(alias):
		f = cve5.NewFetcher()
	default:
		return nil, fmt.Errorf("alias %s is not supported", alias)
	}

	return f.Fetch(ctx, alias)
}
