// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	_ "embed"
	"fmt"
	"path/filepath"
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

	mu              sync.Mutex // protects aliasesToIssues and stats
	aliasesToIssues map[string][]int
	stats           []issuesList

	// issues that have already been marked as duplicate
	duplicates map[int]bool
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

func (t *triage) setup(ctx context.Context, env environment) error {
	t.aliasesToIssues = make(map[string][]int)
	t.stats = make([]issuesList, len(statNames))

	t.issueParser = new(issueParser)
	t.fixer = new(fixer)
	t.xrefer = new(xrefer)
	if err := setupAll(ctx, env, t.issueParser, t.fixer, t.xrefer); err != nil {
		return err
	}

	log.Info("creating alias map for open issues")
	t.duplicates = make(map[int]bool)
	open, err := t.openIssues(ctx)
	if err != nil {
		return err
	}
	for _, iss := range open {
		aliases := t.aliases(ctx, iss)
		for _, a := range aliases {
			t.addAlias(a, iss.Number)
		}
		if iss.HasLabel(labelPossibleDuplicate) || iss.HasLabel(labelDuplicate) {
			t.duplicates[iss.Number] = true
		}
	}
	return nil
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
				log.Warnf("issue #%d: could not auto-set label(s) %s\n\t%v", iss.Number, labels, err)
			}
		}
		t.addStat(iss, statTriaged, "")
	}()

	xrefs := t.findDuplicates(ctx, iss)
	if len(xrefs) != 0 {
		var strs []string
		for ref, aliases := range xrefs {
			strs = append(strs, fmt.Sprintf("#%d shares alias(es) %s with %s", iss.Number,
				strings.Join(aliases, ", "),
				filepath.ToSlash(ref)))
		}
		slices.Sort(strs)
		t.addStat(iss, statDuplicate, strings.Join(strs, listItem))
		labels = append(labels, labelPossibleDuplicate)
	}

	mp := t.canonicalModule(modulePath(iss))
	pr, notGo := t.modulePriority(mp)
	t.addStat(iss, toStat(pr.Priority), pr.Reason)

	if notGo != nil {
		t.addStat(iss, statNotGo, notGo.Reason)
		labels = append(labels, labelPossiblyNotGo)
	}

	if pr.Priority == priority.High {
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

func (t *triage) aliases(ctx context.Context, iss *issues.Issue) []string {
	aliases := aliases(iss)
	if len(aliases) == 0 {
		return nil
	}
	return t.allAliases(ctx, aliases)
}

func (t *triage) findDuplicates(ctx context.Context, iss *issues.Issue) map[string][]string {
	aliases := t.aliases(ctx, iss)
	if len(aliases) == 0 {
		log.Infof("issue #%d: skipping duplicate search (no aliases found)", iss.Number)
		return nil
	}

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

		// Find other open issues with this alias.
		for _, dup := range t.lookupAlias(a) {
			if iss.Number == dup {
				continue
			}
			// If the other issue is already marked as a duplicate,
			// we don't need to mark this one.
			if t.duplicates[dup] {
				continue
			}
			ref := t.ic.Reference(dup)
			xrefs[ref] = append(xrefs[ref], a)
			t.duplicates[iss.Number] = true
		}
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
