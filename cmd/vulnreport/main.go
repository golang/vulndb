// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command vulnreport provides a tool for creating a YAML vulnerability report for
// x/vulndb.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/build"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/stdlib"
)

var (
	localRepoPath       = flag.String("local-cve-repo", "", "path to local repo, instead of cloning remote")
	issueRepo           = flag.String("issue-repo", "github.com/golang/vulndb", "repo to create issues in")
	githubToken         = flag.String("ghtoken", os.Getenv("VULN_GITHUB_ACCESS_TOKEN"), "GitHub access token")
	skipExportedSymbols = flag.Bool("skip-exported", false, "for fix, don't look for exported symbols")
)

func main() {
	ctx := context.Background()
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: vulnreport [cmd] [filename.yaml]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  create [githubIssueNumber]: creates a new vulnerability YAML report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  lint filename.yaml ...: lints vulnerability YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  newcve filename.yaml ...: creates CVEs report from the provided YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  fix filename.yaml ...: fixes and reformats YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  set-dates filename.yaml ...: sets PublishDate of YAML reports\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	names := flag.Args()[1:]
	switch cmd {
	case "create":
		if *githubToken == "" {
			flag.Usage()
			log.Fatalf("githubToken must be provided")
		}
		if len(names) != 1 {
			log.Fatal("need one ID")
		}
		githubID, err := strconv.Atoi(names[0])
		if err != nil {
			log.Fatal(err)
		}
		repoPath := cvelistrepo.URL
		if *localRepoPath != "" {
			repoPath = *localRepoPath
		}
		if err := create(ctx, githubID, *githubToken, *issueRepo, repoPath); err != nil {
			log.Fatal(err)
		}
	case "lint":
		if err := multi(lint, names); err != nil {
			log.Fatal(err)
		}
	case "newcve":
		if err := multi(newCVE, names); err != nil {
			log.Fatal(err)
		}
	case "fix":
		var GHSAsByCVE map[string][]string
		if *githubToken == "" {
			fmt.Println("flag -ghtoken not provided, so not fixing GHSAs")
		} else {
			fmt.Println("querying GitHub for GHSAs...")
			var err error
			GHSAsByCVE, err = loadGHSAsByCVE(ctx, *githubToken)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("fixing...")
		}
		f := func(name string) error { return fix(name, GHSAsByCVE) }
		if err := multi(f, names); err != nil {
			log.Fatal(err)
		}
	case "set-dates":
		repo, err := gitrepo.Open(ctx, ".")
		if err != nil {
			log.Fatal(err)
		}
		commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.MainReference, "reports/")
		if err != nil {
			log.Fatal(err)
		}
		f := func(name string) error { return setDates(name, commitDates) }
		if err := multi(f, names); err != nil {
			log.Fatal(err)
		}

	default:
		flag.Usage()
		log.Fatalf("unsupported command: %q", cmd)
	}
}

func multi(f func(string) error, args []string) error {
	for _, arg := range args {
		if err := f(arg); err != nil {
			return err
		}
	}
	return nil
}
func create(ctx context.Context, issueNumber int, ghToken, issueRepo, repoPath string) (err error) {
	defer derrors.Wrap(&err, "create(%d)", issueNumber)
	owner, repoName, err := gitrepo.ParseGitHubRepo(issueRepo)
	if err != nil {
		return err
	}
	c := issues.NewGitHubClient(owner, repoName, ghToken)
	// Get GitHub issue.
	iss, err := c.GetIssue(ctx, issueNumber)
	if err != nil {
		return err
	}
	// Parse CVE ID from GitHub issue.
	parts := strings.Fields(iss.Title)
	var modulePath string
	for _, p := range parts {
		if strings.HasSuffix(p, ":") && p != "x/vulndb:" {
			modulePath = strings.TrimSuffix(p, ":")
			break
		}
	}
	cveID := parts[len(parts)-1]
	if !strings.HasPrefix(cveID, "CVE") {
		return fmt.Errorf("expected last element of title to be the CVE ID; got %q", iss.Title)
	}
	cve, err := cvelistrepo.FetchCVE(ctx, repoPath, cveID)
	if err != nil {
		return err
	}
	r := report.CVEToReport(cve, modulePath)
	addTODOs(r)
	return r.Write(fmt.Sprintf("reports/GO-2021-%04d.yaml", issueNumber))
}

const todo = "TODO: fill this out"

// addTODOs adds "TODO" comments to unfilled fields of r.
func addTODOs(r *report.Report) {
	if r.Module == "" && !stdlib.Contains(r.Module) {
		r.Module = todo
	}
	if r.Package == "" {
		r.Package = todo
	}
	if r.Description == "" {
		r.Description = todo
	}
	if r.Credit == "" {
		r.Credit = todo
	}
	if len(r.CVEs) == 0 {
		r.CVEs = []string{todo}
	}
	if r.Links.PR == "" {
		r.Links.PR = todo
	}
	if r.Links.Commit == "" {
		r.Links.Commit = todo
	}
	if len(r.Versions) == 0 {
		r.Versions = []report.VersionRange{{
			Introduced: todo,
			Fixed:      todo,
		}}
	}
	if len(r.Symbols) == 0 {
		r.Symbols = []string{todo}
	}
}

func lint(filename string) (err error) {
	defer derrors.Wrap(&err, "lint(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	if lints := r.Lint(); len(lints) > 0 {
		return fmt.Errorf("lint returned errors:\n\t %s", strings.Join(lints, "\n\t"))
	}
	return nil
}

func fix(filename string, GHSAsByCVE map[string][]string) (err error) {
	defer derrors.Wrap(&err, "fix(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if lints := r.Lint(); len(lints) > 0 {
		r.Fix()
	}
	if !*skipExportedSymbols {
		if _, err := addExportedReportSymbols(r); err != nil {
			return err
		}
	}
	if GHSAsByCVE != nil {
		fixGHSAs(r, GHSAsByCVE)
	}

	// Write unconditionally in order to format.
	return r.Write(filename)
}

func addExportedReportSymbols(r *report.Report) (bool, error) {
	if r.Module == "" || len(r.Symbols) == 0 {
		return false, nil
	}
	if len(r.OS) > 0 || len(r.Arch) > 0 {
		return false, errors.New("specific GOOS/GOARCH not yet implemented")
	}
	rc := newReportClient(r)
	added := false
	syms, err := findExportedSymbols(r.Module, r.Package, rc)
	if err != nil {
		return false, err
	}
	if len(syms) > 0 {
		added = true
		r.DerivedSymbols = syms
	}
	for i, ap := range r.AdditionalPackages {
		syms, err := findExportedSymbols(ap.Module, ap.Package, rc)
		if err != nil {
			return false, err
		}
		if len(syms) > 0 {
			added = true
			// Need to start from r because r.AdditionalPackages is a slice of values.
			r.AdditionalPackages[i].DerivedSymbols = syms
		}
	}
	return added, nil
}

func findExportedSymbols(module, pkgPath string, c *reportClient) (_ []string, err error) {
	defer derrors.Wrap(&err, "addExportedSymbols(%q, %q)", module, pkgPath)

	if pkgPath == "" {
		pkgPath = module
	}
	pkgs, err := loadPackage(&packages.Config{}, pkgPath)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, errors.New("no packages found")
	}
	// First package should match package path and module.
	if pkgs[0].PkgPath != pkgPath {
		return nil, fmt.Errorf("first package had import path %s, wanted %s", pkgs[0].PkgPath, pkgPath)
	}
	if pm := pkgs[0].Module; pm == nil || pm.Path != module {
		return nil, fmt.Errorf("got module %v, expected %s", pm, module)
	}
	newsyms, err := exportedFunctions(pkgs, c)
	if err != nil {
		return nil, err
	}
	var newslice []string
	for s := range newsyms {
		newslice = append(newslice, s)
	}
	sort.Strings(newslice)
	return newslice, nil
}

// loadPackage loads the package at the given import path, with enough
// information for constructing a call graph.
func loadPackage(cfg *packages.Config, importPath string) ([]*packages.Package, error) {
	cfg.Mode |= packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg.BuildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(build.Default.BuildTags, ","))}
	pkgs, err := packages.Load(cfg, importPath)
	if err != nil {
		return nil, err
	}
	var msgs []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			msgs = append(msgs, err.Msg)
		}
	})
	if len(msgs) > 0 {
		return nil, fmt.Errorf("packages.Load:\n%s", strings.Join(msgs, "\n"))
	}
	return pkgs, nil
}

// setDates sets the PublishedDate of the report at filename to the oldest
// commit date in the repo that contains that file. (It may someday also set a
// last-modified date, hence the plural.) Since it looks at the commits from
// origin/master, it will only work for reports that are already submitted. Thus
// it isn't useful to run when you're working on a report, only at a later time.
//
// It isn't crucial to run this for every report, because the same logic exists
// in gendb, ensuring that every report has a PublishedDate before being
// transformed into a DB entry. The advantage of using this command is that
// the dates become permanent (if you create and submit a CL after running it).
//
// This intentionally does not set the LastModified of the report: While the
// publication date of a report may be expected not to change, the modification
// date can. Always using the git history as the source of truth for the
// last-modified date avoids confusion if the report YAML and the git history
// disagree.
func setDates(filename string, dates map[string]gitrepo.Dates) (err error) {
	defer derrors.Wrap(&err, "setDates(%q)", filename)

	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if !r.Published.IsZero() {
		return nil
	}
	d, ok := dates[filename]
	if !ok {
		return fmt.Errorf("can't find git repo commit dates for %q", filename)
	}
	r.Published = d.Oldest
	return r.Write(filename)
}

func newCVE(filename string) (err error) {
	defer derrors.Wrap(&err, "newCVE(%q)", filename)
	cve, err := report.ToCVE(filename)
	if err != nil {
		return err
	}

	// We need to use an encoder so that it doesn't escape angle
	// brackets.
	e := json.NewEncoder(os.Stdout)
	e.SetEscapeHTML(false)
	e.SetIndent("", "\t")
	return e.Encode(cve)
}

// loadGHSAsByCVE returns a map from CVE ID to GHSA IDs.
// It does this by using the GitHub API to list all Go security
// advisories with CVEs.
func loadGHSAsByCVE(ctx context.Context, accessToken string) (_ map[string][]string, err error) {
	defer derrors.Wrap(&err, "loadGHSAsByCVE")

	const withCVE = true
	sas, err := ghsa.List(ctx, accessToken, time.Time{}, withCVE)
	if err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for _, sa := range sas {
		for _, id := range sa.Identifiers {
			if id.Type == "CVE" {
				m[id.Value] = append(m[id.Value], sa.PrettyID())
			}
		}
	}
	return m, nil
}

// fixGHSAs replaces r.GHSAs with a sorted list of GitHub Security
// Advisory IDs that correspond to the CVEs.
func fixGHSAs(r *report.Report, GHSAsByCVE map[string][]string) {
	var gids []string
	for _, cid := range r.CVEs {
		gids = append(gids, GHSAsByCVE[cid]...)
	}
	sort.Strings(gids)
	r.GHSAs = gids
}
