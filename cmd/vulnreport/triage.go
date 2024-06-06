// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/cmd/vulnreport/priority"
	"golang.org/x/vulndb/internal/issues"
)

type triage struct {
	*xrefer
	*issueParser
	*fixer

	mu               sync.Mutex // protects aliasesToIssues and stats
	aliasesToIssues  map[string][]int
	modulesToImports map[string]int
	stats            []issuesList
}

func (*triage) name() string { return "triage" }

func (*triage) usage() (string, string) {
	const desc = "determines priority and finds likely duplicates of the given Github issue (with no args, looks at all open issues)"
	return "<no args> | " + ghIssueArgs, desc
}

func (t *triage) close() error {
	log.Outf("triaged %d issues:%s%s",
		len(t.stats[statTriaged]), listItem, strings.Join(toStrings(t.stats[:len(t.stats)-1]), listItem))
	// Print the command to create all high priority reports.
	if len(t.stats[statHighPriority]) > 0 {
		log.Outf("helpful commands:\n  $ vulnreport create %s", t.stats[statHighPriority].issNums())
	}
	return nil
}

func toStrings(stats []issuesList) (strs []string) {
	for i, s := range stats {
		strs = append(strs, fmt.Sprintf("%d %s", len(s), statNames[i]))
	}
	return strs
}

func (t *triage) setup(ctx context.Context) error {
	t.aliasesToIssues = make(map[string][]int)
	t.stats = make([]issuesList, len(statNames))
	m, err := priority.LoadModuleMap()
	if err != nil {
		return nil
	}
	t.modulesToImports = m

	t.fixer = new(fixer)
	t.issueParser = new(issueParser)
	t.xrefer = new(xrefer)
	return setupAll(ctx, t.fixer, t.issueParser, t.xrefer)
}

func (t *triage) skip(input any) string {
	iss := input.(*issues.Issue)

	if iss.HasLabel(labelDirect) {
		return "direct external report"
	}

	if isExcluded(iss) {
		return "excluded"
	}

	if !*force && iss.HasLabel(labelTriaged) {
		return "already triaged; use -f to force re-triage"
	}

	return skip(iss, t.xrefer)
}

func (t *triage) run(ctx context.Context, input any) (err error) {
	iss := input.(*issues.Issue)
	t.triage(ctx, iss)
	return nil
}

func (t *triage) triage(ctx context.Context, iss *issues.Issue) {
	labels := []string{labelTriaged}
	defer func() {
		// Preserve any existing labels.
		labels = append(labels, iss.Labels...)
		slices.Sort(labels)
		labels = slices.Compact(labels)
		if *dry {
			log.Infof("issue #%d: would set labels: [%s]", iss.Number, strings.Join(labels, ", "))
		} else {
			if err := t.ic.SetLabels(ctx, iss.Number, labels); err != nil {
				log.Warnf("issue #%d: could not auto-set label(s) %s", iss.Number, labels)
			}
		}
		t.addStat(iss, statTriaged, "")
	}()

	xrefs := t.findDuplicates(ctx, iss)
	if len(xrefs) != 0 {
		var strs []string
		for ref, aliases := range xrefs {
			strs = append(strs, fmt.Sprintf("#%d shares alias(es) %s with %s", iss.Number, strings.Join(aliases, ", "), ref))
		}
		t.addStat(iss, statDuplicate, strings.Join(strs, listItem))
		labels = append(labels, labelPossibleDuplicate)
	}

	mp := t.canonicalModule(modulePath(iss))
	tr := priority.Analyze(mp, t.rc.ReportsByModule(mp), t.modulesToImports)
	t.addStat(iss, toStat(tr.Priority), tr.Reason)

	if tr.NotGo {
		t.addStat(iss, statNotGo, tr.NotGoReason)
		labels = append(labels, labelPossiblyNotGo)
	}

	if tr.Priority == priority.High {
		labels = append(labels, labelHighPriority)
	}
}

func toStat(p priority.Priority) int {
	switch p {
	case priority.Unknown:
		return statUnknownPriority
	case priority.Low:
		return statLowPriority
	case priority.High:
		return statHighPriority
	default:
		panic(fmt.Sprintf("unknown priority %d", p))
	}
}

func (t *triage) findDuplicates(ctx context.Context, iss *issues.Issue) map[string][]string {
	aliases := aliases(iss)

	if len(aliases) == 0 {
		log.Infof("issue #%d: skipping duplicate search (no aliases found)", iss.Number)
		return nil
	}

	aliases = t.allAliases(ctx, aliases)
	xrefs := make(map[string][]string)
	for _, a := range aliases {
		// Find existing reports with this alias.
		if reports := t.rc.ReportsByAlias(a); len(reports) != 0 {
			for _, r := range reports {
				fname, err := r.YAMLFilename()
				if err != nil {
					fname = r.ID
				}
				xrefs[fname] = append(xrefs[fname], a)
			}
		}

		// Find other issues with this alias.
		// Note: this currently only operates on other issues that have
		// been seen by the triage command, not all issues on the tracker.
		for _, issNum := range t.lookupAlias(a) {
			ref := t.ic.Reference(issNum)
			xrefs[ref] = append(xrefs[ref], a)
		}

		t.addAlias(a, iss.Number)
	}

	return xrefs
}

func (t *triage) lookupAlias(a string) []int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.aliasesToIssues[a]
}

func (t *triage) addAlias(a string, n int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.aliasesToIssues[a] = append(t.aliasesToIssues[a], n)
}

func (t *triage) addStat(iss *issues.Issue, stat int, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var lg func(string, ...any)
	switch stat {
	case statTriaged:
		// no-op
		lg = func(string, ...any) {}
	case statLowPriority:
		lg = log.Infof
	case statHighPriority, statDuplicate, statNotGo:
		lg = log.Outf
	case statUnknownPriority:
		lg = log.Warnf
	default:
		panic(fmt.Sprintf("BUG: unknown stat: %d", stat))
	}

	t.stats[stat] = append(t.stats[stat], iss)
	lg("issue %s is %s%s%s", t.ic.Reference(iss.Number), statNames[stat], listItem, reason)
}

const (
	statHighPriority = iota
	statLowPriority
	statUnknownPriority

	statDuplicate
	statNotGo

	statTriaged
)

var statNames = []string{
	statHighPriority:    "high priority",
	statLowPriority:     "low priority",
	statUnknownPriority: "unknown priority",
	statDuplicate:       "likely duplicate",
	statNotGo:           "possibly not Go",
	statTriaged:         "triaged",
}

type issuesList []*issues.Issue

func (i issuesList) issNums() string {
	var is []string
	for _, iss := range i {
		is = append(is, strconv.Itoa(iss.Number))
	}
	return strings.Join(is, " ")
}
