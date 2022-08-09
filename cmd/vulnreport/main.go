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
	"go/types"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"
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
	localRepoPath = flag.String("local-cve-repo", "", "path to local repo, instead of cloning remote")
	issueRepo     = flag.String("issue-repo", "github.com/golang/vulndb", "repo to create issues in")
	githubToken   = flag.String("ghtoken", os.Getenv("VULN_GITHUB_ACCESS_TOKEN"), "GitHub access token")
	skipSymbols   = flag.Bool("skip-symbols", false, "for lint and fix, don't load package for symbols checks")
	alwaysFixGHSA = flag.Bool("always-fix-ghsa", false, "for fix, always update GHSAs")
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
		fmt.Fprintf(flag.CommandLine.Output(), "  commit filename.yaml ...: creates new commits for YAML reports\n")
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
			log.Fatalf("invalid GitHub issue ID: %q: %v", names[0], err)
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
	case "commit":
		f := func(name string) error { return commit(ctx, name, *githubToken) }
		if err := multi(f, names); err != nil {
			log.Fatal(err)
		}
	case "newcve":
		if err := multi(newCVE, names); err != nil {
			log.Fatal(err)
		}
	case "fix":
		f := func(name string) error { return fix(ctx, name, *githubToken) }
		if err := multi(f, names); err != nil {
			log.Fatal(err)
		}
	case "set-dates":
		repo, err := gitrepo.Open(ctx, ".")
		if err != nil {
			log.Fatal(err)
		}
		commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.MainReference, "data/reports/")
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
	// Parse CVE or GHSA ID from GitHub issue.
	parts := strings.Fields(iss.Title)
	var modulePath string
	for _, p := range parts {
		if strings.HasSuffix(p, ":") && p != "x/vulndb:" {
			modulePath = strings.TrimSuffix(p, ":")
			break
		}
	}
	id := parts[len(parts)-1]
	var r *report.Report
	switch {
	case strings.HasPrefix(id, "CVE"):
		cve, err := cvelistrepo.FetchCVE(ctx, repoPath, id)
		if err != nil {
			return err
		}
		r = report.CVEToReport(cve, modulePath)
	case strings.HasPrefix(id, "GHSA"):
		ghsa, err := ghsa.FetchGHSA(ctx, ghToken, id)
		if err != nil {
			return err
		}
		r = report.GHSAToReport(ghsa, modulePath)
	default:
		return fmt.Errorf("expected last element of title to be the CVE ID or GHSA ID; got %q", iss.Title)
	}
	addTODOs(r)
	var year int
	if !iss.CreatedAt.IsZero() {
		year = iss.CreatedAt.Year()
	}
	filename := fmt.Sprintf("data/reports/GO-%04d-%04d.yaml", year, issueNumber)
	if err := r.Write(filename); err != nil {
		return err
	}
	fmt.Println(filename)
	return nil
}

const todo = "TODO: fill this out"

// addTODOs adds "TODO" comments to unfilled fields of r.
func addTODOs(r *report.Report) {
	if len(r.Packages) == 0 {
		r.Packages = append(r.Packages, report.Package{})
	}
	for i := range r.Packages {
		p := &r.Packages[i]
		if p.Module == "" && !stdlib.Contains(p.Module) {
			p.Module = todo
		}
		if p.Package == "" {
			p.Package = todo
		}
		if len(p.Versions) == 0 {
			p.Versions = []report.VersionRange{{
				Introduced: todo,
				Fixed:      todo,
			}}
		}
		if p.VulnerableAt == "" {
			p.VulnerableAt = todo
		}
		if len(p.Symbols) == 0 {
			p.Symbols = []string{todo}
		}
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
	if len(r.Links.Context) == 0 {
		r.Links.Context = []string{todo}
	}
}

func lint(filename string) (err error) {
	defer derrors.Wrap(&err, "lint(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	if lints := r.Lint(filename); len(lints) > 0 {
		return fmt.Errorf("lint returned errors:\n\t %s", strings.Join(lints, "\n\t"))
	}
	return nil
}

func fix(ctx context.Context, filename string, accessToken string) (err error) {
	defer derrors.Wrap(&err, "fix(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if lints := r.Lint(filename); len(lints) > 0 {
		r.Fix()
	}
	if !*skipSymbols {
		if _, err := checkReportSymbols(r); err != nil {
			return err
		}
	}
	if err := fixGHSAs(ctx, r, accessToken); err != nil {
		return err
	}

	// Write unconditionally in order to format.
	return r.Write(filename)
}

func checkReportSymbols(r *report.Report) (bool, error) {
	if len(r.OS) > 0 || len(r.Arch) > 0 {
		return false, errors.New("specific GOOS/GOARCH not yet implemented")
	}
	rc := newReportClient(r)
	added := false
	for i, p := range r.Packages {
		if len(p.Symbols) == 0 {
			continue
		}
		syms, err := findExportedSymbols(p, rc)
		if err != nil {
			return false, err
		}
		if !slices.Equal(syms, r.Packages[i].DerivedSymbols) {
			added = true
			r.Packages[i].DerivedSymbols = syms
		}
	}
	return added, nil
}

func findExportedSymbols(p report.Package, c *reportClient) (_ []string, err error) {
	defer derrors.Wrap(&err, "addExportedSymbols(%q, %q)", p.Module, p.Package)

	if p.VulnerableAt == "" {
		fmt.Fprintf(os.Stderr, "%v: no vulnerable_at version, skipping symbol checks.\n", p.Package)
		return nil, nil
	}

	module := p.Module
	pkgPath := p.Package
	if pkgPath == "" {
		pkgPath = module
	}

	cleanup, err := changeToTempDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if err := run("go", "mod", "init", "go.dev/_"); err != nil {
		return nil, err
	}
	std := false
	if !stdlib.Contains(p.Module) {
		pkgPathAndVersion := pkgPath + "@" + p.VulnerableAt.V()
		if err := run("go", "get", pkgPathAndVersion); err != nil {
			return nil, err
		}
	} else {
		std = true
		gover := runtime.Version()
		ver := semverForGoVersion(gover)
		if ver == "" || !affected(c.entry, ver.V()) {
			fmt.Fprintf(os.Stderr, "%v: Go version %q is not in a vulnerable range, skipping symbol checks.\n", pkgPath, gover)
			return nil, nil
		}
		if ver != p.VulnerableAt {
			fmt.Fprintf(os.Stderr, "%v: WARNING: Go version %q does not match vulnerable_at version %q.\n", pkgPath, ver, p.VulnerableAt)
		}
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
	if std {
		if pm := pkgs[0].Module; std && pm != nil {
			return nil, fmt.Errorf("got module %v, expected nil", pm)
		}
	} else {
		if pm := pkgs[0].Module; pm == nil || pm.Path != module {
			return nil, fmt.Errorf("got module %v, expected %s", pm, module)
		}
	}

	// Check to see that all symbols actually exist in the package.
	// This should perhaps be a lint check, but lint doesn't
	// load/typecheck packages at the moment, so do it here for now.
	for _, sym := range p.Symbols {
		if typ, method, ok := strings.Cut(sym, "."); ok {
			n, ok := pkgs[0].Types.Scope().Lookup(typ).(*types.TypeName)
			if !ok {
				fmt.Fprintf(os.Stderr, "%v: type not found\n", typ)
				continue
			}
			m, _, _ := types.LookupFieldOrMethod(n.Type(), true, pkgs[0].Types, method)
			if m == nil {
				fmt.Fprintf(os.Stderr, "%v: method not found\n", sym)
			}
		} else {
			_, ok := pkgs[0].Types.Scope().Lookup(typ).(*types.Func)
			if !ok {
				fmt.Fprintf(os.Stderr, "%v: func not found\n", typ)
			}
		}
	}

	newsyms, err := exportedFunctions(pkgs, c)
	if err != nil {
		return nil, err
	}
	var newslice []string
	for s := range newsyms {
		if s == "init" {
			// Exclude init funcs from consideration.
			//
			// Assume that if init is calling a vulnerable symbol,
			// it is doing so in a safe fashion (for example, the
			// function might be vulnerable only when provided with
			// untrusted input).
			continue
		}
		if !slices.Contains(p.Symbols, s) {
			newslice = append(newslice, s)
		}
	}
	sort.Strings(newslice)
	return newslice, nil
}

var reportRegexp = regexp.MustCompile(`^reports/GO-\d\d\d\d-(\d+)\.yaml$`)

func commit(ctx context.Context, filename, accessToken string) (err error) {
	defer derrors.Wrap(&err, "commit(%q)", filename)
	m := reportRegexp.FindStringSubmatch(filename)
	if len(m) != 2 {
		return fmt.Errorf("%v: not a report filename", filename)
	}
	issueID := m[1]

	// Ignore errors. If anything is really wrong with the report, we'll
	// detect it on re-linting below.
	_ = fix(ctx, filename, accessToken)

	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if lints := r.Lint(filename); len(lints) > 0 {
		fmt.Fprintf(os.Stderr, "%v: contains lint warnings, not committing\n", filename)
		for _, l := range lints {
			fmt.Fprintln(os.Stderr, l)
		}
		fmt.Fprintln(os.Stderr)
		return nil
	}

	// Exec the git command rather than using go-git so as to run commit hooks
	// and give the user a chance to edit the commit message.
	irun := func(name string, arg ...string) error {
		cmd := exec.Command(name, arg...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if err := irun("git", "add", filename); err != nil {
		fmt.Fprintf(os.Stderr, "git add: %v\n", err)
		return nil
	}
	var cves, action string
	if r.CVEMetadata != nil {
		action = "Updates"
		cves = r.CVEMetadata.ID
	} else {
		action = "Fixes"
		cves = strings.Join(r.CVEs, ", ")
	}
	msg := fmt.Sprintf("x/vulndb: add %v for %v\n\n%s golang/vulndb#%v\n",
		filename, cves, action, issueID)
	if err := irun("git", "commit", "-m", msg, "-e", filename); err != nil {
		fmt.Fprintf(os.Stderr, "git commit: %v\n", err)
		return nil
	}

	return nil
}

// Regexp for matching go tags. The groups are:
// 1  the major.minor version
// 2  the patch version, or empty if none
// 3  the entire prerelease, if present
// 4  the prerelease type ("beta" or "rc")
// 5  the prerelease number
var tagRegexp = regexp.MustCompile(`^go(\d+\.\d+)(\.\d+|)((beta|rc)(\d+))?$`)

// versionForTag returns the semantic version for a Go version string,
// or "" if the version string doesn't correspond to a Go release or beta.
func semverForGoVersion(v string) report.Version {
	m := tagRegexp.FindStringSubmatch(v)
	if m == nil {
		return ""
	}
	version := m[1]
	if m[2] != "" {
		version += m[2]
	} else {
		version += ".0"
	}
	if m[3] != "" {
		version += "-" + m[4] + "." + m[5]
	}
	return report.Version(version)
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

func changeToTempDir() (cleanup func(), _ error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vulnreport")
	if err != nil {
		return nil, err
	}
	cleanup = func() {
		_ = os.RemoveAll(dir)
		_ = os.Chdir(cwd)
	}
	if err := os.Chdir(dir); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, err
}

func run(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.Stderr.Write(out)
	}
	return err
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
func fixGHSAs(ctx context.Context, r *report.Report, accessToken string) error {
	if accessToken == "" {
		return nil
	}
	if len(r.GHSAs) > 0 && !*alwaysFixGHSA {
		return nil
	}
	m := map[string]struct{}{}
	for _, cid := range r.CVEs {
		sas, err := ghsa.ListForCVE(ctx, accessToken, cid)
		if err != nil {
			return err
		}
		for _, sa := range sas {
			m[sa.PrettyID()] = struct{}{}
		}
	}
	var gids []string
	for gid := range m {
		gids = append(gids, gid)
	}
	sort.Strings(gids)
	r.GHSAs = gids
	return nil
}
