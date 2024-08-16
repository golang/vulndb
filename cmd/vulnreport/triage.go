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
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/triage/priority"
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
		if iss.HasLabel(labelDuplicate) {
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
	comments := []string{}
	defer func() {
		t.editIssue(ctx, iss, labels, comments)
		t.addStat(iss, statTriaged, "")
	}()

	dupes := t.findDuplicates(ctx, iss)
	if len(dupes) != 0 {
		var strs []string
		for d, aliases := range dupes {
			ref := t.ic.Reference(d.iss)
			if d.fname != "" {
				ref = filepath.ToSlash(d.fname)
			}
			strs = append(strs, fmt.Sprintf("#%d shares alias(es) %s with %s", iss.Number,
				strings.Join(aliases, ", "), ref))
			comments = append(comments, fmt.Sprintf("Duplicate of #%d", d.iss))
		}
		slices.Sort(strs)
		t.addStat(iss, statDuplicate, strings.Join(strs, listItem))
		labels = append(labels, labelDuplicate)
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

func (t *triage) editIssue(ctx context.Context, iss *issues.Issue, labels, comments []string) {
	// Preserve any existing labels.
	labels = append(labels, iss.Labels...)

	// Sort and de-duplicate.
	slices.Sort(labels)
	labels = slices.Compact(labels)
	slices.Sort(comments)
	comments = slices.Compact(comments)

	if *dry {
		if len(labels) != 0 {
			log.Infof("issue #%d: would set labels: [%s]", iss.Number, strings.Join(labels, ", "))
		}
		if len(comments) != 0 {
			log.Infof("issue #%d: would add comments: [%s]", iss.Number, strings.Join(comments, ", "))
		}
		return
	}

	if err := t.ic.SetLabels(ctx, iss.Number, labels); err != nil {
		log.Warnf("issue #%d: could not auto-set label(s) %s\n\t%v", iss.Number, labels, err)
	}

	// TODO(tatianabradley): Read existing comments to ensure we aren't
	// posting the same comment twice.
	// (This requires an extra Github API request.)
	if err := t.ic.AddComments(ctx, iss.Number, comments); err != nil {
		log.Warnf("issue #%d: could not add comment(s) %s\n\t%v", iss.Number, comments, err)
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

type vuln struct {
	// The issue number for this vulnerability.
	iss int
	// The filename of the report for this issue.
	fname string
}

// findDuplicates returns a map of duplicate issues to the aliases
// that they share with the given issue.
func (t *triage) findDuplicates(ctx context.Context, iss *issues.Issue) map[vuln][]string {
	aliases := t.aliases(ctx, iss)
	if len(aliases) == 0 {
		log.Infof("issue #%d: skipping duplicate search (no aliases found)", iss.Number)
		return nil
	}

	duplicates := make(map[vuln][]string)
	for _, a := range aliases {
		// Find existing reports with this alias.
		if reports := t.rc.ReportsByAlias(a); len(reports) != 0 {
			for _, r := range reports {
				fname, err := r.YAMLFilename()
				if err != nil {
					log.Warnf("could not get filename of duplicate report: %s", err)
					continue
				}
				_, _, iss, err := report.ParseFilepath(fname)
				if err != nil {
					log.Warnf("could not parse duplicate report: %s", err)
					continue
				}
				d := vuln{
					iss:   iss,
					fname: fname,
				}
				duplicates[d] = append(duplicates[d], a)
			}
		}

		// Find other open issues with this alias.
		for _, issNum := range t.lookupAlias(a) {
			if iss.Number == issNum {
				continue
			}
			// If the other issue is already marked as a duplicate,
			// we don't need to mark this one.
			if t.duplicates[issNum] {
				continue
			}
			d := vuln{
				iss: issNum,
				// no report yet
			}
			duplicates[d] = append(duplicates[d], a)
			t.duplicates[iss.Number] = true
		}
	}

	return duplicates
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
