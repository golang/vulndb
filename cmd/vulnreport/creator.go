// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

type creator struct {
	assignee string
	created  []*report.Report

	*fixer
	*xrefer
	*suggester
}

func (c *creator) setup(ctx context.Context) (err error) {
	user := *user
	if user == "" {
		user = os.Getenv("GITHUB_USER")
	}
	c.assignee = user

	c.fixer = new(fixer)
	c.xrefer = new(xrefer)
	if *useAI {
		c.suggester = new(suggester)
	}
	return setupAll(ctx, c.fixer, c.xrefer, c.suggester)
}

func (c *creator) close() error {
	log.Infof("created %d reports", len(c.created))
	return c.suggester.close()
}

func (c *creator) skipReason(iss *issues.Issue) string {
	if c.assignee != "" && iss.Assignee != c.assignee {
		return fmt.Sprintf("assignee = %q, not %q", iss.Assignee, c.assignee)
	}

	return c.xrefer.skipReason(iss)
}

func (x *xrefer) skipReason(iss *issues.Issue) string {
	if iss.HasLabel(labelDuplicate) {
		return "duplicate issue"
	}

	if iss.HasLabel(labelSuggestedEdit) {
		return "suggested edit"
	}

	if iss.HasLabel(labelPossibleDuplicate) {
		return "possible duplicate"
	}

	if iss.HasLabel(labelPossiblyNotGo) {
		return "possibly not Go"
	}

	if x.rc.HasReport(iss.Number) {
		return "already has report"
	}

	return ""
}

func (c *creator) reportFromIssue(ctx context.Context, iss *issues.Issue) error {
	return c.reportFromMeta(ctx, &reportMeta{
		id:         iss.NewGoID(),
		excluded:   excludedReason(iss),
		modulePath: modulePath(iss),
		aliases:    aliases(iss),
	})
}

func (c *creator) reportFromMeta(ctx context.Context, meta *reportMeta) error {
	// Find the underlying module if the "module" provided is actually a package path.
	if module, err := c.pc.FindModule(meta.modulePath); err == nil { // no error
		meta.modulePath = module
	}

	var src report.Source
	aliases := c.allAliases(ctx, meta.aliases)
	src, ok := c.sourceFromBestAlias(ctx, aliases, *preferCVE)
	if ok {
		log.Infof("creating report %s based on %s (picked from [%s])", meta.id, src.SourceID(), strings.Join(aliases, ", "))
	} else {
		log.Info("no suitable alias found, creating basic report")
	}

	status := report.Reviewed
	if meta.unreviewed {
		status = report.Unreviewed
	}

	r := report.New(src, c.pc,
		report.WithGoID(meta.id),
		report.WithModulePath(meta.modulePath),
		report.WithAliases(aliases),
		report.WithReviewStatus(status),
	)

	// Find any additional aliases referenced by the source aliases.
	c.addMissingAliases(ctx, r)

	if c.suggester != nil {
		suggestions, err := c.suggest(ctx, r, 1)
		if err != nil {
			r.AddNote(report.NoteTypeCreate, "failed to get AI-generated suggestions")
			log.Warnf("failed to get AI-generated suggestions for %s: %v", r.ID, err)
		} else {
			log.Infof("applying AI-generated suggestion for %s", r.ID)
			applySuggestion(r, suggestions[0])
		}
	}

	if *populateSymbols {
		log.Infof("attempting to auto-populate symbols for %s (this may take a while...)", r.ID)
		if err := symbols.Populate(r, false); err != nil {
			r.AddNote(report.NoteTypeCreate, "failed to auto-populate symbols")
			log.Warnf("could not auto-populate symbols: %s", err)
		} else {
			if err := checkReportSymbols(r); err != nil {
				log.Warnf("auto-populated symbols have error(s): %s", err)
			}
		}
	}

	switch {
	case meta.excluded != "":
		r = &report.Report{
			ID: meta.id,
			Modules: []*report.Module{
				{
					Module: meta.modulePath,
				},
			},
			Excluded: meta.excluded,
			CVEs:     r.CVEs,
			GHSAs:    r.GHSAs,
		}
	case meta.unreviewed:
		r.Description = ""
		addNotes := true
		if fixed := c.fix(ctx, r, addNotes); fixed {
			if err := writeDerived(r); err != nil {
				return err
			}
		}
	default:
		// Regular, full-length reports.
		addTODOs(r)
		xrefs, err := c.xref(r)
		if err != nil {
			log.Warnf("could not get cross-references: %s", err)
		} else if len(xrefs) != 0 {
			log.Infof("found cross-references: %s", xrefs)
		}
	}

	if err := writeReport(r); err != nil {
		return err
	}

	c.created = append(c.created, r)
	return nil
}

const (
	labelDuplicate         = "duplicate"
	labelDirect            = "Direct External Report"
	labelSuggestedEdit     = "Suggested Edit"
	labelHighPriority      = "high priority"
	labelPossibleDuplicate = "possible duplicate"
	labelPossiblyNotGo     = "possibly not Go"
)

func excludedReason(iss *issues.Issue) report.ExcludedReason {
	for _, label := range iss.Labels {
		if reason, ok := report.FromLabel(label); ok {
			return reason
		}
	}
	return ""
}

func modulePath(iss *issues.Issue) string {
	for _, p := range strings.Fields(iss.Title) {
		if p == "x/vulndb:" {
			continue
		}
		if strings.HasSuffix(p, ":") || strings.Contains(p, "/") {
			// Remove backslashes.
			return strings.ReplaceAll(strings.TrimSuffix(p, ":"), "\"", "")
		}
	}
	return ""
}

func aliases(iss *issues.Issue) (aliases []string) {
	for _, p := range strings.Fields(iss.Title) {
		if idstr.IsAliasType(p) {
			aliases = append(aliases, strings.TrimSuffix(p, ","))
		}
	}
	return aliases
}

// Data that can be combined with a source vulnerability
// to create a new report.
type reportMeta struct {
	id         string
	modulePath string
	aliases    []string
	excluded   report.ExcludedReason
	unreviewed bool // create basic report with no TODOs and no description
}

const todo = "TODO: "

// addTODOs adds "TODO" comments to unfilled fields of r.
func addTODOs(r *report.Report) {
	if r.Excluded != "" {
		return
	}
	if len(r.Modules) == 0 {
		r.Modules = append(r.Modules, &report.Module{
			Packages: []*report.Package{{}},
		})
	}
	for _, m := range r.Modules {
		if m.Module == "" {
			m.Module = todo + "affected module path"
		}
		if len(m.Versions) == 0 {
			m.Versions = []report.VersionRange{{
				Introduced: todo + "introduced version (blank if unknown)",
				Fixed:      todo + "fixed version",
			}}
		}
		if m.VulnerableAt == "" {
			m.VulnerableAt = todo + "a version at which the package is vulnerable"
		}
		if len(m.Packages) == 0 {
			m.Packages = []*report.Package{
				{
					Package: todo + "affected package path(s) - blank if all",
				},
			}
		}
		for _, p := range m.Packages {
			if p.Package == "" {
				p.Package = todo + "affected package path"
			}
			if len(p.Symbols) == 0 {
				p.Symbols = []string{todo + "affected symbol(s) - blank if all"}
			}
		}
	}
	if r.Summary == "" {
		r.Summary = todo + "short (one phrase) summary of the form '<Problem> in <module>(s)'"
	}
	if r.Description == "" {
		r.Description = todo + "description of the vulnerability"
	}
	if len(r.Credits) == 0 {
		r.Credits = []string{todo + "who discovered/reported this vulnerability (optional)"}
	}
	if len(r.CVEs) == 0 {
		r.CVEs = []string{todo + "CVE id(s) for this vulnerability"}
	}
	addReferenceTODOs(r)
}

// addReferenceTODOs adds a TODO for each important reference type not
// already present in the report.
func addReferenceTODOs(r *report.Report) {
	todos := []*report.Reference{
		{Type: osv.ReferenceTypeAdvisory, URL: "TODO: canonical security advisory"},
		{Type: osv.ReferenceTypeReport, URL: "TODO: issue tracker link"},
		{Type: osv.ReferenceTypeFix, URL: "TODO: PR or commit (commit preferred)"}}

	types := make(map[osv.ReferenceType]bool)
	for _, r := range r.References {
		types[r.Type] = true
	}
	for _, todo := range todos {
		if !types[todo.Type] {
			r.References = append(r.References, todo)
		}
	}
}
