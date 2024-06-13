// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

type creator struct {
	assignee string
	created  []*yamlReport

	// If non-zero, use this review status
	// instead of the default for new reports.
	reviewStatus report.ReviewStatus

	*fixer
	*xrefer
	*suggester
}

func (c *creator) setup(ctx context.Context, env environment) (err error) {
	user := *user
	if user == "" {
		user = os.Getenv("GITHUB_USER")
	}
	c.assignee = user

	rs, ok := report.ToReviewStatus(*reviewStatus)
	if !ok {
		return fmt.Errorf("invalid -status=%s", rs)
	}
	c.reviewStatus = rs

	c.fixer = new(fixer)
	c.xrefer = new(xrefer)
	if *useAI {
		c.suggester = new(suggester)
	}
	return setupAll(ctx, env, c.fixer, c.xrefer, c.suggester)
}

func (c *creator) skip(input any) string {
	iss := input.(*issues.Issue)

	if c.assignee != "" && iss.Assignee != c.assignee {
		return fmt.Sprintf("assignee = %q, not %q", iss.Assignee, c.assignee)
	}

	return skip(iss, c.xrefer)
}

func skip(iss *issues.Issue, x *xrefer) string {
	if iss.HasLabel(labelOutOfScope) {
		return "out of scope"
	}

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
	r, err := c.reportFromMeta(ctx, &reportMeta{
		id:           iss.NewGoID(),
		excluded:     excludedReason(iss),
		modulePath:   modulePath(iss),
		aliases:      aliases(iss),
		reviewStatus: reviewStatusOf(iss, c.reviewStatus),
	})
	if err != nil {
		return err
	}
	return c.write(ctx, r)
}

func reviewStatusOf(iss *issues.Issue, reviewStatus report.ReviewStatus) report.ReviewStatus {
	d := defaultReviewStatus(iss)
	// If a valid review status is provided, it overrides the priority label.
	if reviewStatus != 0 {
		if d != reviewStatus {
			log.Warnf("issue #%d: should be %s based on label(s) but this was overridden with the -status=%s flag", iss.Number, d, reviewStatus)
		}
		return reviewStatus
	}
	return d
}

func defaultReviewStatus(iss *issues.Issue) report.ReviewStatus {
	if iss.HasLabel(labelHighPriority) ||
		iss.HasLabel(labelDirect) ||
		iss.HasLabel(labelFirstParty) {
		return report.Reviewed
	}

	return report.Unreviewed
}

func (c *creator) reportFromMeta(ctx context.Context, meta *reportMeta) (*yamlReport, error) {
	// Find the underlying module if the "module" provided is actually a package path.
	if module, err := c.pc.FindModule(meta.modulePath); err == nil { // no error
		meta.modulePath = module
	}

	var src report.Source
	aliases := c.allAliases(ctx, meta.aliases)
	src, ok := c.sourceFromBestAlias(ctx, aliases, *preferCVE)
	if ok {
		log.Infof("%s: picked %s as best source alias (from [%s])", meta.id, src.SourceID(), strings.Join(aliases, ", "))
	} else {
		log.Infof("%s: no suitable alias found, creating basic report", meta.id)
	}

	raw := report.New(src, c.pc,
		report.WithGoID(meta.id),
		report.WithModulePath(meta.modulePath),
		report.WithAliases(aliases),
		report.WithReviewStatus(meta.reviewStatus),
	)

	if meta.excluded != "" {
		raw = &report.Report{
			ID: meta.id,
			Modules: []*report.Module{
				{
					Module: meta.modulePath,
				},
			},
			Excluded: meta.excluded,
			CVEs:     raw.CVEs,
			GHSAs:    raw.GHSAs,
		}
	}

	fname, err := raw.YAMLFilename()
	if err != nil {
		return nil, err
	}
	r := &yamlReport{Report: raw, Filename: fname}

	// Find any additional aliases referenced by the source aliases.
	r.addMissingAliases(ctx, c.aliasFinder)

	if c.suggester != nil {
		suggestions, err := c.suggest(ctx, r, 1)
		if err != nil {
			r.AddNote(report.NoteTypeCreate, "failed to get AI-generated suggestions")
			log.Warnf("%s: failed to get AI-generated suggestions: %v", r.ID, err)
		} else {
			log.Infof("%s: applying AI-generated suggestion", r.ID)
			r.applySuggestion(suggestions[0])
		}
	}

	if *populateSymbols {
		log.Infof("%s: attempting to auto-populate symbols (this may take a while...)", r.ID)
		if err := symbols.Populate(r.Report, false); err != nil {
			r.AddNote(report.NoteTypeCreate, "failed to auto-populate symbols")
			log.Warnf("%s: could not auto-populate symbols: %s", r.ID, err)
		} else {
			if err := r.checkSymbols(); err != nil {
				log.Warnf("%s: auto-populated symbols have error(s): %s", r.ID, err)
			}
		}
	}

	switch {
	case meta.excluded != "":
		// nothing
	case meta.reviewStatus == report.Unreviewed:
		r.Description = ""
		addNotes := true
		// Package-level data is often wrong/incomplete, which could lead
		// to false negatives, so remove it for unreviewed reports.
		// TODO(tatianabradley): instead of removing all package-level data,
		// consider doing a surface-level check such as making sure packages are
		// known to pkgsite, but skip symbol-level checks.
		r.removePackages()
		r.removeUnreachableRefs()
		_ = c.fix(ctx, r, addNotes)
	default:
		// Regular, full-length reports.
		addTODOs(r)
		if xrefs := c.xref(r); len(xrefs) != 0 {
			log.Infof("%s: found cross-references: %s", r.ID, xrefs)
		}
	}
	return r, nil
}

func (r *yamlReport) removePackages() {
	for _, m := range r.Report.Modules {
		m.Packages = nil
	}
}

func (r *yamlReport) removeUnreachableRefs() {
	r.Report.References = slices.DeleteFunc(r.Report.References, func(r *report.Reference) bool {
		resp, err := http.Head(r.URL)
		if err != nil {
			return true
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusNotFound
	})
}

func (c *creator) write(ctx context.Context, r *yamlReport) error {
	if r.IsReviewed() || r.IsExcluded() {
		if err := c.fileWriter.write(r); err != nil {
			return err
		}
	} else { // unreviewed
		if err := c.fixAndWriteAll(ctx, r); err != nil {
			return err
		}
	}
	c.created = append(c.created, r)
	return nil
}

const (
	labelDuplicate         = "duplicate"
	labelDirect            = "Direct External Report"
	labelSuggestedEdit     = "Suggested Edit"
	labelTriaged           = "triaged"
	labelHighPriority      = "high priority"
	labelFirstParty        = "first party"
	labelPossibleDuplicate = "possible duplicate"
	labelPossiblyNotGo     = "possibly not Go"
	labelOutOfScope        = "excluded: OUT_OF_SCOPE"
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
	id           string
	modulePath   string
	aliases      []string
	excluded     report.ExcludedReason
	reviewStatus report.ReviewStatus
}

const todo = "TODO: "

// addTODOs adds "TODO" comments to unfilled fields of r.
func addTODOs(r *yamlReport) {
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
func addReferenceTODOs(r *yamlReport) {
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
