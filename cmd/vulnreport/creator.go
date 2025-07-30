// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
	"golang.org/x/vulndb/internal/triage/priority"
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

	// indicates that there is already a report for this
	// vuln but the report needs to be updated
	if iss.HasLabel(labelNeedsAlias) {
		return "existing report needs alias"
	}

	if iss.HasLabel(labelPossiblyNotGo) {
		return "possibly not Go"
	}

	if x.rc.HasReport(iss.Number) {
		return "already has report"
	}

	return ""
}

func (c *creator) newReportFromIssue(ctx context.Context, iss *issues.Issue) error {
	id := iss.NewGoID()
	r, err := c.reportFromMeta(ctx, &reportMeta{
		id:           id,
		excluded:     excludedReason(iss),
		modulePath:   modulePath(iss),
		aliases:      aliases(iss),
		reviewStatus: reviewStatusOf(iss, c.reviewStatus),
		originalCVE:  originalCVE(iss),
	})
	if err != nil {
		return err
	}
	if r.Withdrawn != nil {
		return fmt.Errorf("new regular report should not be created for withdrawn vulnerability; %s", withdrawnGuidance(id, iss.Number))
	}
	return c.write(ctx, r)
}

func originalCVE(iss *issues.Issue) string {
	aliases := aliases(iss)
	if iss.HasLabel(labelFirstParty) && len(aliases) == 1 && idstr.IsCVE(aliases[0]) {
		return aliases[0]
	}
	return ""
}

func reviewStatusOf(iss *issues.Issue, reviewStatus report.ReviewStatus) report.ReviewStatus {
	d := defaultReviewStatus(iss)
	// If a valid review status is provided, it overrides the priority label.
	if reviewStatus != 0 {
		if d != reviewStatus {
			log.Warnf("issue #%d: would be %s based on label(s) but this was overridden with the -status=%s flag", iss.Number, d, reviewStatus)
		}
		return reviewStatus
	}
	return d
}

func defaultReviewStatus(iss *issues.Issue) report.ReviewStatus {
	if iss.HasLabel(labelDirect) ||
		iss.HasLabel(labelFirstParty) {
		return report.Reviewed
	}

	if iss.HasLabel(labelHighPriority) {
		return report.NeedsReview
	}

	return report.Unreviewed
}

func (c *creator) metaToSource(ctx context.Context, meta *reportMeta) report.Source {
	if cveID := meta.originalCVE; cveID != "" {
		log.Infof("%s: creating original report for Go-CNA-assigned %s", meta.id, cveID)
		return report.OriginalCVE(cveID)
	}

	if src := c.sourceFromBestAlias(ctx, meta.aliases, *preferCVE); src != nil {
		log.Infof("%s: picked %s as best source alias (from [%s])", meta.id, src.SourceID(),
			strings.Join(meta.aliases, ", "))
		return src
	}

	log.Infof("%s: no suitable alias found, creating basic report", meta.id)
	return report.Original()
}

func (c *creator) rawReport(ctx context.Context, meta *reportMeta) *report.Report {
	log.Infof("%s: creating new %s report", meta.id, meta.reviewStatus)
	return report.New(c.metaToSource(ctx, meta), c.pxc,
		report.WithGoID(meta.id),
		report.WithModulePath(meta.modulePath),
		report.WithAliases(meta.aliases),
		report.WithReviewStatus(meta.reviewStatus),
		report.WithUnexcluded(meta.unexcluded),
	)
}

func (c *creator) reportFromMeta(ctx context.Context, meta *reportMeta) (*yamlReport, error) {
	// Find the underlying module if the "module" provided is actually a package path.
	if module, err := c.pxc.FindModule(meta.modulePath); err == nil { // no error
		meta.modulePath = module
	}
	meta.aliases = c.allAliases(ctx, meta.aliases)
	raw := c.rawReport(ctx, meta)

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

	// The initial quick triage algorithm doesn't know about all
	// affected modules, so double check the priority after the
	// report is created.
	if raw.IsUnreviewed() && !raw.IsExcluded() {
		pr, _ := c.reportPriority(raw)
		if pr.Priority == priority.High {
			log.Warnf("%s: vuln is high priority and should be NEEDS_REVIEW or REVIEWED; reason: %s", raw.ID, pr.Reason)
			raw.ReviewStatus = report.NeedsReview
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

	if *populateSymbols && raw.NeedsReview() {
		log.Infof("%s: attempting to auto-populate symbols for NEEDS_REVIEW report (this may take a while...)", r.ID)
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
	case raw.IsExcluded():
		// nothing
	case !raw.IsReviewed():
		r.removeUnreachableRefs()
	default:
		// Regular, full-length reports.
		addTODOs(r)
		if xrefs := c.xref(r); len(xrefs) != 0 {
			log.Infof("%s: found cross-references: %s", r.ID, xrefs)
		}
	}
	return r, nil
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
		addNotes := true
		if err := c.fixAndWriteAll(ctx, r, addNotes); err != nil {
			return err
		}
	}
	c.created = append(c.created, r)
	return nil
}

const (
	labelDuplicate     = "duplicate"
	labelDirect        = "Direct External Report"
	labelSuggestedEdit = "Suggested Edit"
	labelNeedsAlias    = "NeedsAlias"
	labelTriaged       = "triaged"
	labelNeedsTriage   = "NeedsTriage"
	labelHighPriority  = "high priority"
	labelFirstParty    = "first party"
	labelPossiblyNotGo = "possibly not Go"
	labelOutOfScope    = "excluded: OUT_OF_SCOPE"
)

func excludedReason(iss *issues.Issue) report.ExcludedType {
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
	id                   string
	modulePath           string
	aliases              []string
	excluded, unexcluded report.ExcludedType
	reviewStatus         report.ReviewStatus
	originalCVE          string
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
			m.Versions = report.Versions{
				report.Introduced(todo + "introduced version (blank if unknown)"),
				report.Fixed(todo + "fixed version"),
			}
		}
		if m.VulnerableAt == nil {
			m.VulnerableAt = report.VulnerableAt(todo + "a version at which the package is vulnerable")
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
	if r.CVEMetadata == nil && len(r.CVEs) == 0 {
		r.CVEs = []string{todo + "CVE id(s) for this vulnerability"}
	}
	if r.CVEMetadata != nil && r.CVEMetadata.CWE == "" {
		r.CVEMetadata.CWE = todo + "CWE ID"
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
