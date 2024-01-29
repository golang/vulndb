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

	"golang.org/x/vulndb/internal/cveclient"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/genericosv"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var (
	preferCVE = flag.Bool("cve", false, "for create, prefer CVEs over GHSAs as canonical source")
	closedOk  = flag.Bool("closed-ok", false, "for create & create-excluded, allow closed issues to be created")
	graphQL   = flag.Bool("graphql", false, "for create, fetch GHSAs from the Github GraphQL API instead of the OSV database")
	issueRepo = flag.String("issue-repo", "github.com/golang/vulndb", "for create, repo locate Github issues")
)

func create(ctx context.Context, issueNumber int, cfg *createCfg) (err error) {
	defer derrors.Wrap(&err, "create(%d)", issueNumber)
	// Get GitHub issue.
	iss, err := cfg.issuesClient.Issue(ctx, issueNumber)
	if err != nil {
		return err
	}

	r, err := createReport(ctx, cfg, iss)
	if err != nil {
		return err
	}

	filename, err := writeReport(r)
	if err != nil {
		return err
	}

	outlog.Println(filename)

	xrefs := xref(filename, r, cfg.existingByFile)
	if len(xrefs) != 0 {
		infolog.Printf("found cross-references:\n%s", xrefs)
	}

	return nil
}

func createExcluded(ctx context.Context, cfg *createCfg) (err error) {
	defer derrors.Wrap(&err, "createExcluded()")
	isses := []*issues.Issue{}
	stateOption := "open"
	if cfg.allowClosed {
		stateOption = "all"
	}
	for _, er := range report.ExcludedReasons {
		label := er.ToLabel()
		tempIssues, err :=
			cfg.issuesClient.Issues(ctx, issues.IssuesOptions{Labels: []string{label}, State: stateOption})
		if err != nil {
			return err
		}
		infolog.Printf("found %d issues with label %s\n", len(tempIssues), label)
		isses = append(isses, tempIssues...)
	}

	var created []string
	for _, iss := range isses {
		// Don't create a report for an issue that already has a report.
		if _, ok := cfg.existingByIssue[iss.Number]; ok {
			infolog.Printf("skipped issue %d which already has a report\n", iss.Number)
			continue
		}

		r, err := createReport(ctx, cfg, iss)
		if err != nil {
			errlog.Printf("skipped issue %d: %v\n", iss.Number, err)
			continue
		}

		filename, err := writeReport(r)
		if err != nil {
			return err
		}

		created = append(created, filename)
	}

	skipped := len(isses) - len(created)
	if skipped > 0 {
		infolog.Printf("skipped %d issue(s)\n", skipped)
	}

	if len(created) == 0 {
		infolog.Printf("no files to commit, exiting")
		return nil
	}

	msg, err := excludedCommitMsg(created)
	if err != nil {
		return err
	}
	if err := gitAdd(created...); err != nil {
		return err
	}
	return gitCommit(msg, created...)
}

type createCfg struct {
	ghsaClient      *ghsa.Client
	issuesClient    *issues.Client
	proxyClient     *proxy.Client
	existingByFile  map[string]*report.Report
	existingByIssue map[int]*report.Report
	allowClosed     bool
}

func setupCreate(ctx context.Context, args []string) ([]int, *createCfg, error) {
	if *githubToken == "" {
		return nil, nil, fmt.Errorf("githubToken must be provided")
	}
	localRepo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		return nil, nil, err
	}
	existingByIssue, existingByFile, err := report.All(localRepo)
	if err != nil {
		return nil, nil, err
	}
	githubIDs, err := parseArgsToGithubIDs(args, existingByIssue)
	if err != nil {
		return nil, nil, err
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return nil, nil, err
	}
	return githubIDs, &createCfg{
		issuesClient:    issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken}),
		ghsaClient:      ghsa.NewClient(ctx, *githubToken),
		proxyClient:     proxy.NewDefaultClient(),
		existingByFile:  existingByFile,
		existingByIssue: existingByIssue,
		allowClosed:     *closedOk,
	}, nil
}

func parseArgsToGithubIDs(args []string, existingByIssue map[int]*report.Report) ([]int, error) {
	var githubIDs []int
	parseGithubID := func(s string) (int, error) {
		id, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("invalid GitHub issue ID: %q", s)
		}
		return id, nil
	}
	for _, arg := range args {
		if !strings.Contains(arg, "-") {
			id, err := parseGithubID(arg)
			if err != nil {
				return nil, err
			}
			githubIDs = append(githubIDs, id)
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
			if existingByIssue[id] != nil {
				continue
			}
			githubIDs = append(githubIDs, id)
		}
	}
	return githubIDs, nil
}

func createReport(ctx context.Context, cfg *createCfg, iss *issues.Issue) (r *report.Report, err error) {
	defer derrors.Wrap(&err, "createReport(%d)", iss.Number)

	parsed, err := parseGithubIssue(iss, cfg.proxyClient, cfg.allowClosed)
	if err != nil {
		return nil, err
	}

	aliases := allAliases(ctx, parsed.aliases, cfg.ghsaClient)
	if alias, ok := pickBestAlias(aliases, *preferCVE); ok {
		infolog.Printf("creating report %s based on %s (picked from [%s])", parsed.id, alias, strings.Join(aliases, ", "))
		r, err = reportFromAlias(ctx, parsed.id, parsed.modulePath, alias, cfg)
		if err != nil {
			return nil, err
		}
	} else {
		infolog.Printf("no alias found, creating basic report for %s", parsed.id)
		r = &report.Report{
			ID: parsed.id,
			Modules: []*report.Module{
				{
					Module: parsed.modulePath,
				},
			}}
	}

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

	// Ensure all source aliases are added to the report.
	r.AddAliases(aliases)

	// Find any additional aliases referenced by the source aliases.
	addMissingAliases(ctx, r, cfg.ghsaClient)

	addTODOs(r)
	return r, nil
}

func parseGithubIssue(iss *issues.Issue, pc *proxy.Client, allowClosed bool) (*parsedIssue, error) {
	parsed := &parsedIssue{
		id: iss.NewGoID(),
	}

	if !allowClosed && iss.State == "closed" {
		return nil, errors.New("issue is closed")
	}

	// Parse labels for excluded and duplicate issues.
	for _, label := range iss.Labels {
		if reason, ok := report.FromLabel(label); ok {
			if parsed.excluded == "" {
				parsed.excluded = reason
			} else {
				return nil, fmt.Errorf("issue has multiple excluded reasons")
			}
		}
		if label == "duplicate" {
			return nil, fmt.Errorf("duplicate issue")
		}
	}

	// Parse elements from GitHub issue title.
	parts := strings.Fields(iss.Title)
	for _, p := range parts {
		switch {
		case p == "x/vulndb:":
			continue
		case cveschema5.IsCVE(p) || ghsa.IsGHSA(p):
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

	if len(parsed.aliases) == 0 {
		infolog.Printf("%q has no CVE or GHSA IDs\n", iss.Title)
	}

	return parsed, nil
}

type parsedIssue struct {
	id         string
	modulePath string
	aliases    []string
	excluded   report.ExcludedReason
}

func excludedCommitMsg(fs []string) (string, error) {
	var issNums []string
	for _, f := range fs {
		_, _, iss, err := report.ParseFilepath(f)
		if err != nil {
			return "", err
		}
		issNums = append(issNums, fmt.Sprintf("Fixes golang/vulndb#%d", iss))
	}

	return fmt.Sprintf(
		`%s: batch add %d excluded reports

Adds excluded reports:
	- %s

%s`,
		report.ExcludedDir,
		len(fs),
		strings.Join(fs, "\n\t- "),
		strings.Join(issNums, "\n")), nil
}

// reportFromBestAlias returns a new report created from the "best" alias in the list.
// For now, it prefers the first GHSA in the list, followed by the first CVE in the list
// (if no GHSA is present). If no GHSAs or CVEs are present, it returns a new empty Report.
func reportFromAlias(ctx context.Context, id, modulePath, alias string, cfg *createCfg) (*report.Report, error) {
	switch {
	case ghsa.IsGHSA(alias) && *graphQL:
		ghsa, err := cfg.ghsaClient.FetchGHSA(ctx, alias)
		if err != nil {
			return nil, err
		}
		r := report.GHSAToReport(ghsa, modulePath, cfg.proxyClient)
		r.ID = id
		return r, nil
	case ghsa.IsGHSA(alias):
		ghsa, err := genericosv.Fetch(alias)
		if err != nil {
			return nil, err
		}
		return ghsa.ToReport(id, cfg.proxyClient), nil
	case cveschema5.IsCVE(alias):
		cve, err := cveclient.Fetch(alias)
		if err != nil {
			// If a CVE is not found, it is most likely a CVE we reserved but haven't
			// published yet.
			infolog.Printf("no published record found for %s, creating basic report", alias)
			return basicReport(id, modulePath), nil
		}
		return report.CVE5ToReport(cve, id, modulePath, cfg.proxyClient), nil
	}

	infolog.Printf("alias %s is not a CVE or GHSA, creating basic report", alias)
	return basicReport(id, modulePath), nil
}

func basicReport(id, modulePath string) *report.Report {
	return &report.Report{
		ID: id,
		Modules: []*report.Module{
			{
				Module: modulePath,
			},
		},
	}
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
