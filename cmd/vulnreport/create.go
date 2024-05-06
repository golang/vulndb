// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/genai"
	"golang.org/x/vulndb/internal/genericosv"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

var (
	preferCVE       = flag.Bool("cve", false, "for create, prefer CVEs over GHSAs as canonical source")
	closedOk        = flag.Bool("closed-ok", false, "for create & create-excluded, allow closed issues to be created")
	graphQL         = flag.Bool("graphql", false, "for create, fetch GHSAs from the Github GraphQL API instead of the OSV database")
	issueRepo       = flag.String("issue-repo", "github.com/golang/vulndb", "for create, repo locate Github issues")
	useAI           = flag.Bool("ai", false, "for create, use AI to write draft summary and description when creating report")
	populateSymbols = flag.Bool("symbols", false, "for create, attempt to auto-populate symbols")
)

type create struct {
	gc          *ghsa.Client
	ic          *issues.Client
	pc          *proxy.Client
	ac          *genai.GeminiClient
	rc          *report.Client
	allowClosed bool
}

func (create) name() string { return "create" }

func (create) usage() (string, string) {
	const desc = "creates a new vulnerability YAML report"
	return ghIssueArgs, desc
}

func (c *create) setup(ctx context.Context) error {
	if *githubToken == "" {
		return fmt.Errorf("githubToken must be provided")
	}
	localRepo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		return err
	}
	rc, err := report.NewClient(localRepo)
	if err != nil {
		return err
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return err
	}
	var aiClient *genai.GeminiClient
	if *useAI {
		aiClient, err = genai.NewGeminiClient(ctx)
		if err != nil {
			return err
		}
	}
	c.ic = issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken})
	c.gc = ghsa.NewClient(ctx, *githubToken)
	c.pc = proxy.NewDefaultClient()
	c.rc = rc
	c.allowClosed = *closedOk
	c.ac = aiClient
	return nil
}

func (*create) close() error { return nil }

func (c *create) run(ctx context.Context, issueNumber string) (err error) {
	n, err := strconv.Atoi(issueNumber)
	if err != nil {
		return err
	}

	if c.rc.HasReport(n) {
		log.Infof("issue #%d already has a report, skipping", n)
		return nil
	}

	iss, err := c.ic.Issue(ctx, n)
	if err != nil {
		return err
	}

	r, err := createReport(ctx, iss, c.pc, c.gc, c.ac, c.allowClosed)
	if err != nil {
		return err
	}

	addTODOs(r)

	filename, err := writeReport(r)
	if err != nil {
		return err
	}

	log.Out(filename)

	xrefs := xrefInner(filename, r, c.rc)
	if len(xrefs) != 0 {
		log.Infof("found cross-references:\n%s", xrefs)
	}

	return nil
}

func (c *create) parseArgs(ctx context.Context, args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}
	return argsToIDs(args)
}

func argsToIDs(args []string) ([]string, error) {
	var githubIDs []string
	parseGithubID := func(s string) (int, error) {
		id, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("invalid GitHub issue ID: %q", s)
		}
		return id, nil
	}
	for _, arg := range args {
		if !strings.Contains(arg, "-") {
			_, err := parseGithubID(arg)
			if err != nil {
				return nil, err
			}
			githubIDs = append(githubIDs, arg)
			continue
		}
		from, to, _ := strings.Cut(arg, "-")
		fromID, err := parseGithubID(from)
		if err != nil {
			return nil, err
		}
		toID, err := parseGithubID(to)
		if err != nil {
			return nil, err
		}
		if fromID > toID {
			return nil, fmt.Errorf("%v > %v", fromID, toID)
		}
		for id := fromID; id <= toID; id++ {
			githubIDs = append(githubIDs, strconv.Itoa(id))
		}
	}
	return githubIDs, nil
}

func createReport(ctx context.Context, iss *issues.Issue, pc *proxy.Client, gc *ghsa.Client, ac *genai.GeminiClient, allowClosed bool) (r *report.Report, err error) {
	if iss.HasLabel(labelDuplicate) {
		return nil, fmt.Errorf("duplicate issue")
	}

	if !allowClosed && iss.State == "closed" {
		return nil, errors.New("issue is closed")
	}

	parsed, err := parseGithubIssue(iss, pc)
	if err != nil {
		return nil, err
	}

	if len(parsed.aliases) == 0 {
		log.Infof("#%d (%q) has no CVE or GHSA IDs", iss.Number, iss.Title)
	}

	r = reportFromAliases(ctx, parsed.id, parsed.modulePath, parsed.aliases,
		pc, gc, ac)

	if parsed.excluded != "" {
		r = &report.Report{
			ID: parsed.id,
			Modules: []*report.Module{
				{
					Module: parsed.modulePath,
				},
			},
			Excluded: parsed.excluded,
			CVEs:     r.CVEs,
			GHSAs:    r.GHSAs,
		}
	}
	return r, nil
}

func fetch(ctx context.Context, alias string, gc *ghsa.Client) report.Source {
	var f report.Fetcher
	switch {
	case idstr.IsGHSA(alias):
		if *graphQL {
			f = gc
		} else {
			f = genericosv.NewFetcher()
		}
	case idstr.IsCVE(alias):
		f = cve5.NewFetcher()
	default:
		log.Warnf("alias %s is not supported, creating basic report", alias)
		return report.Original()
	}

	src, err := f.Fetch(ctx, alias)
	if err != nil {
		log.Warnf("could not fetch %s (err = %q), creating basic report", alias, err)
		return report.Original()
	}

	return src
}

func reportFromAliases(ctx context.Context, id, modulePath string, aliases []string,
	pc *proxy.Client, gc *ghsa.Client, ac *genai.GeminiClient) *report.Report {

	var src report.Source
	aliases = allAliases(ctx, aliases, gc)
	if alias, ok := pickBestAlias(aliases, *preferCVE); ok {
		log.Infof("creating report %s based on %s (picked from [%s])", id, alias, strings.Join(aliases, ", "))
		src = fetch(ctx, alias, gc)
	} else {
		log.Info("no alias found, creating basic report")
		src = report.Original()
	}

	r := report.New(src, pc,
		report.WithGoID(id),
		report.WithModulePath(modulePath),
		report.WithAliases(aliases),
		report.WithCreated(time.Now()),
	)

	// Find any additional aliases referenced by the source aliases.
	addMissingAliases(ctx, r, gc)

	if ac != nil {
		suggestions, err := suggestions(ctx, ac, r, 1)
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

	return r
}

const (
	labelDuplicate = "duplicate"
	labelDirect    = "Direct External Report"
)

func parseGithubIssue(iss *issues.Issue, pc *proxy.Client) (*parsedIssue, error) {
	parsed := &parsedIssue{
		id: iss.NewGoID(),
	}

	// Find any excluded labels.
	for _, label := range iss.Labels {
		if reason, ok := report.FromLabel(label); ok {
			if parsed.excluded == "" {
				parsed.excluded = reason
			} else {
				return nil, fmt.Errorf("issue has multiple excluded reasons")
			}
		}
	}

	// Parse elements from GitHub issue title.
	parts := strings.Fields(iss.Title)
	for _, p := range parts {
		switch {
		case p == "x/vulndb:":
			continue
		case idstr.IsAliasType(p):
			parsed.aliases = append(parsed.aliases, strings.TrimSuffix(p, ","))
		case strings.HasSuffix(p, ":") || strings.Contains(p, "/"):
			// Remove backslashes.
			parsed.modulePath = strings.ReplaceAll(strings.TrimSuffix(p, ":"), "\"", "")
			// Find the underlying module if this is a package path.
			if module, err := pc.FindModule(parsed.modulePath); err == nil { // no error
				parsed.modulePath = module
			}
		}
	}

	return parsed, nil
}

type parsedIssue struct {
	id         string
	modulePath string
	aliases    []string
	excluded   report.ExcludedReason
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

func writeReport(r *report.Report) (string, error) {
	filename, err := r.YAMLFilename()
	if err != nil {
		return "", err
	}
	if err := r.Write(filename); err != nil {
		return "", err
	}
	return filename, nil
}
