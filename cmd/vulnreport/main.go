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
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/database"
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
		fmt.Fprintf(flag.CommandLine.Output(), "  xref filename.yaml ...: prints cross references for YAML reports\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 3 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	// Create operates on github issue IDs instead of filenames, so it is
	// separated from the other commands.
	if cmd == "create" {
		githubIDs, cfg, err := setupCreate(args)
		if err != nil {
			log.Fatal(err)
		}
		for _, githubID := range githubIDs {
			if err := create(ctx, githubID, cfg); err != nil {
				log.Fatal(err)
			}
		}
		return
	}

	var cmdFunc func(string) error
	switch cmd {
	case "lint":
		cmdFunc = lint
	case "commit":
		cmdFunc = func(name string) error { return commit(ctx, name, *githubToken) }
	case "newcve":
		cmdFunc = newCVE
	case "fix":
		cmdFunc = func(name string) error { return fix(ctx, name, *githubToken) }
	case "set-dates":
		repo, err := gitrepo.Open(ctx, ".")
		if err != nil {
			log.Fatal(err)
		}
		commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.MainReference, "data/reports/")
		if err != nil {
			log.Fatal(err)
		}
		cmdFunc = func(name string) error { return setDates(name, commitDates) }
	case "xref":
		_, existingByFile, err := existingReports()
		if err != nil {
			log.Fatal(err)
		}
		cmdFunc = func(name string) error {
			r, err := report.Read(name)
			if err != nil {
				return err
			}
			fmt.Println(name)
			fmt.Print(xref(name, r, existingByFile))
			return nil
		}
	default:
		flag.Usage()
		log.Fatalf("unsupported command: %q", cmd)
	}

	// Run the command on each argument.
	for _, arg := range args {
		arg, err := argToFilename(arg)
		if err != nil {
			log.Fatal(err)
		}
		if err := cmdFunc(arg); err != nil {
			log.Fatal(err)
		}
	}
}

func argToFilename(arg string) (string, error) {
	if _, err := os.Stat(arg); err != nil {
		// If arg isn't a file, see if it might be an issue ID
		// with an existing report.
		for _, padding := range []string{"", "0", "00", "000"} {
			m, _ := filepath.Glob("data/*/GO-*-" + padding + arg + ".yaml")
			if len(m) == 1 {
				return m[0], nil
			}
		}
		return "", fmt.Errorf("%s is not a valid filename or issue ID with existing report", arg)
	}
	return arg, nil
}

func existingReports() (byIssue map[int]*report.Report, byFile map[string]*report.Report, err error) {
	defer derrors.Wrap(&err, "existingReports")
	byIssue = make(map[int]*report.Report)
	byFile = make(map[string]*report.Report)
	for _, dir := range []string{"data/reports", "data/excluded"} {
		f, err := os.Open(dir)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		names, err := f.Readdirnames(0)
		if err != nil {
			return nil, nil, err
		}
		for _, name := range names {
			name := filepath.Join(dir, name)
			m := reportRegexp.FindStringSubmatch(name)
			if len(m) != 3 {
				continue
			}
			id := m[2]
			iss, err := strconv.Atoi(id)
			if err != nil {
				continue
			}
			r, err := report.Read(name)
			if err != nil {
				continue
			}
			byIssue[iss] = r
			byFile[name] = r
		}
	}
	return byIssue, byFile, nil
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

type createCfg struct {
	ghToken        string
	repoPath       string
	issuesClient   issues.Client
	existingByFile map[string]*report.Report
}

func setupCreate(args []string) ([]int, *createCfg, error) {
	if *githubToken == "" {
		flag.Usage()
		log.Fatalf("githubToken must be provided")
	}
	existingByIssue, existingByFile, err := existingReports()
	if err != nil {
		log.Fatal(err)
	}
	githubIDs, err := parseArgsToGithubIDs(args, existingByIssue)
	if err != nil {
		log.Fatal(err)
	}
	if len(githubIDs) > 1 {
		// Maybe we should automatically maintain a local clone of the
		// cvelist repo, but for now we can avoid repeatedly fetching it
		// when iterating over a list of reports.
		return nil, nil, fmt.Errorf("git clone %v to a local directory, and set -local-cve-repo to that path", cvelistrepo.URL)
	}
	repoPath := cvelistrepo.URL
	if *localRepoPath != "" {
		repoPath = *localRepoPath
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return nil, nil, err
	}
	return githubIDs, &createCfg{
		ghToken:        *githubToken,
		repoPath:       repoPath,
		issuesClient:   issues.NewGitHubClient(owner, repoName, *githubToken),
		existingByFile: existingByFile,
	}, nil
}

func create(ctx context.Context, issueNumber int, cfg *createCfg) (err error) {
	defer derrors.Wrap(&err, "create(%d)", issueNumber)
	// Get GitHub issue.
	iss, err := cfg.issuesClient.GetIssue(ctx, issueNumber, issues.GetIssueOptions{GetLabels: true})
	if err != nil {
		return err
	}
	// Parse labels for excluded issues.
	var excluded report.ExcludedReason
	for _, label := range iss.Labels {
		if strings.HasPrefix(label, "excluded: ") {
			excluded = report.ExcludedReason(strings.TrimPrefix(label, "excluded: "))
			break
		}
		if label == "duplicate" {
			fmt.Printf("skipping issue %v: duplicate\n", issueNumber)
			return nil
		}
	}
	// Parse CVE or GHSA ID from GitHub issue.
	parts := strings.Fields(iss.Title)
	var (
		modulePath string
		cves       []string
		ghsas      []string
	)
	for _, p := range parts {
		switch {
		case strings.HasSuffix(p, ":") && p != "x/vulndb:":
			modulePath = strings.TrimSuffix(p, ":")
		case strings.HasPrefix(p, "CVE"):
			cves = append(cves, strings.TrimSuffix(p, ","))
		case strings.HasPrefix(p, "GHSA"):
			ghsas = append(ghsas, strings.TrimSuffix(p, ","))
		}
	}
	if len(ghsas) == 0 && len(cves) > 0 {
		for _, cve := range cves {
			sas, err := ghsa.ListForCVE(ctx, cfg.ghToken, cve)
			if err != nil {
				return err
			}
			for _, sa := range sas {
				ghsas = append(ghsas, sa.GHSA())
			}
		}
		slices.Sort(ghsas)
		ghsas = slices.Compact(ghsas)
	}

	var r *report.Report
	switch {
	case len(ghsas) > 0:
		ghsa, err := ghsa.FetchGHSA(ctx, cfg.ghToken, ghsas[0])
		if err != nil {
			return err
		}
		r = report.GHSAToReport(ghsa, modulePath)
	case len(cves) > 0:
		cve, err := cvelistrepo.FetchCVE(ctx, cfg.repoPath, cves[0])
		if err != nil {
			return err
		}
		r = report.CVEToReport(cve, modulePath)
	default:
		return fmt.Errorf("expected title to contain at least one CVE ID or GHSA ID; got %q", iss.Title)
	}

	r.CVEs = append(r.CVEs, cves...)
	slices.Sort(r.CVEs)
	r.CVEs = slices.Compact(r.CVEs)

	r.GHSAs = append(r.GHSAs, ghsas...)
	slices.Sort(r.GHSAs)
	r.GHSAs = slices.Compact(r.GHSAs)

	if excluded != "" {
		r = &report.Report{
			Excluded: excluded,
			CVEs:     r.CVEs,
			GHSAs:    r.GHSAs,
		}
	}

	addTODOs(r)
	var year int
	if !iss.CreatedAt.IsZero() {
		year = iss.CreatedAt.Year()
	}
	dir := "reports"
	if excluded != "" {
		dir = "excluded"
	}
	filename := fmt.Sprintf("data/%s/GO-%04d-%04d.yaml", dir, year, issueNumber)
	if err := r.Write(filename); err != nil {
		return err
	}
	fmt.Println(filename)
	fmt.Print(xref(filename, r, cfg.existingByFile))
	return nil
}

// xref returns cross-references for a report: Information about other reports
// for the same CVE, GHSA, or module.
func xref(rname string, r *report.Report, existingByFile map[string]*report.Report) string {
	out := &strings.Builder{}
	mods := make(map[string]bool)
	for _, m := range r.Modules {
		if m.Module != "" {
			mods[m.Module] = true
		}
	}
	existingByID := make(map[string][]string)
	basename := filepath.Base(rname)
	for fname, rr := range existingByFile {
		if basename == filepath.Base(fname) {
			continue
		}
		for _, cve := range rr.CVEs {
			if slices.Contains(r.CVEs, cve) {
				existingByID[cve] = append(existingByID[cve], fname)
			}
		}
		for _, ghsa := range rr.GHSAs {
			if slices.Contains(r.GHSAs, ghsa) {
				existingByID[ghsa] = append(existingByID[ghsa], fname)
			}
		}
		for _, m := range rr.Modules {
			if mods[m.Module] {
				k := "Module " + m.Module
				existingByID[k] = append(existingByID[k], fname)
			}
		}
	}
	// This sorts as CVEs, GHSAs, and then modules.
	for _, id := range sorted(maps.Keys(existingByID)) {
		for _, fname := range sorted(existingByID[id]) {
			fmt.Fprintf(out, "%v appears in %v", id, fname)
			e := existingByFile[fname].Excluded
			if e != "" {
				fmt.Fprintf(out, "  %v", e)
			}
			fmt.Fprintf(out, "\n")
		}
	}
	return out.String()
}

func sorted[E constraints.Ordered](s []E) []E {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

const todo = "TODO: fill this out"

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
			m.Module = todo
		}
		if len(m.Versions) == 0 {
			m.Versions = []report.VersionRange{{
				Introduced: todo,
				Fixed:      todo,
			}}
		}
		if m.VulnerableAt == "" {
			m.VulnerableAt = todo
		}
		for _, p := range m.Packages {
			if p.Package == "" {
				p.Package = todo
			}
			if len(p.Symbols) == 0 {
				p.Symbols = []string{todo}
			}
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
	r.References = append(r.References, []*report.Reference{
		{Type: report.ReferenceTypeAdvisory, URL: "TODO: canonical security advisory"},
		{Type: report.ReferenceTypeArticle, URL: "TODO: article or blog post"},
		{Type: report.ReferenceTypeReport, URL: "TODO: issue tracker link"},
		{Type: report.ReferenceTypeFix, URL: "TODO: PR or commit"},
		{Type: report.ReferenceTypeWeb, URL: "TODO: web page of some unspecified kind"},
	}...)
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
		if err := checkReportSymbols(r); err != nil {
			return err
		}
	}
	if err := fixGHSAs(ctx, r, accessToken); err != nil {
		return err
	}
	// Write unconditionally in order to format.
	if err := r.Write(filename); err != nil {
		return err
	}
	// Write the OSV for non-excluded reports.
	if r.Excluded == "" {
		entry := database.GenerateOSVEntry(filename, time.Time{}, r)
		j, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			return err
		}
		jfilename := fmt.Sprintf("data/osv/%v.json", entry.ID)
		if err := os.WriteFile(jfilename, j, 0644); err != nil {
			return err
		}
	}
	return nil
}

func checkReportSymbols(r *report.Report) error {
	for _, m := range r.Modules {
		for _, p := range m.Packages {
			p.DerivedSymbols = nil
		}
	}
	rc := newReportClient(r)
	for _, m := range r.Modules {
		for _, p := range m.Packages {
			if len(p.Symbols) == 0 {
				continue
			}
			if len(p.GOOS) > 0 || len(p.GOARCH) > 0 {
				return errors.New("specific GOOS/GOARCH not yet implemented")
			}
			syms, err := findExportedSymbols(m, p, rc)
			if err != nil {
				return err
			}
			p.DerivedSymbols = syms
		}
	}
	return nil
}

func findExportedSymbols(m *report.Module, p *report.Package, c *reportClient) (_ []string, err error) {
	defer derrors.Wrap(&err, "addExportedSymbols(%q, %q)", m.Module, p.Package)

	if m.VulnerableAt == "" {
		fmt.Fprintf(os.Stderr, "%v: no vulnerable_at version, skipping symbol checks.\n", p.Package)
		return nil, nil
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
	if m.Module != stdlib.ModulePath {
		pkgPathAndVersion := p.Package + "@" + m.VulnerableAt.V()
		if err := run("go", "get", pkgPathAndVersion); err != nil {
			return nil, err
		}
	} else {
		std = true
		gover := runtime.Version()
		ver := semverForGoVersion(gover)
		if ver == "" || !affected(c.entry, ver.V()) {
			fmt.Fprintf(os.Stderr, "%v: Go version %q is not in a vulnerable range, skipping symbol checks.\n", p.Package, gover)
			return p.DerivedSymbols, nil
		}
		if ver != m.VulnerableAt {
			fmt.Fprintf(os.Stderr, "%v: WARNING: Go version %q does not match vulnerable_at version %q.\n", p.Package, ver, m.VulnerableAt)
		}
	}

	pkgs, err := loadPackage(&packages.Config{}, p.Package)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, errors.New("no packages found")
	}
	// First package should match package path and module.
	if pkgs[0].PkgPath != p.Package {
		return nil, fmt.Errorf("first package had import path %s, wanted %s", pkgs[0].PkgPath, p.Package)
	}
	if std {
		if pm := pkgs[0].Module; std && pm != nil {
			return nil, fmt.Errorf("got module %v, expected nil", pm)
		}
	} else {
		if pm := pkgs[0].Module; pm == nil || pm.Path != m.Module {
			return nil, fmt.Errorf("got module %v, expected %s", pm, m.Module)
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

var reportRegexp = regexp.MustCompile(`^(data/\w+)/GO-\d\d\d\d-(\d+)\.yaml$`)

func commit(ctx context.Context, filename, accessToken string) (err error) {
	defer derrors.Wrap(&err, "commit(%q)", filename)
	m := reportRegexp.FindStringSubmatch(filename)
	if len(m) != 3 {
		return fmt.Errorf("%v: not a report filename", filename)
	}
	issueID := m[2]

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
	var osvfilename string
	if r.Excluded == "" {
		osvfilename = "data/osv/" + strings.TrimSuffix(filepath.Base(filename), ".yaml") + ".json"
		if err := irun("git", "add", osvfilename); err != nil {
			fmt.Fprintf(os.Stderr, "git add %v: %v\n", osvfilename, err)
			return nil
		}
	}

	var externalAdvisories string
	action := "Fixes"
	switch {
	case r.CVEMetadata != nil:
		action = "Updates"
		externalAdvisories = r.CVEMetadata.ID
	case len(r.CVEs) > 0:
		externalAdvisories = strings.Join(r.CVEs, ", ")
	case len(r.GHSAs) > 0:
		externalAdvisories = strings.Join(r.GHSAs, ", ")
	default:
		externalAdvisories = "[no CVE or GHSA]"
	}

	folder := m[1]
	msg := fmt.Sprintf("%s: add %s for %s\n\n%s golang/vulndb#%s\n",
		folder,
		strings.TrimPrefix(filename, fmt.Sprintf("%s/", folder)), externalAdvisories, action, strings.TrimPrefix(issueID, "0"))
	args := []string{"commit", "-m", msg, "-e", filename}
	if osvfilename != "" {
		args = append(args, osvfilename)
	}
	if err := irun("git", args...); err != nil {
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
// advisories.
func loadGHSAsByCVE(ctx context.Context, accessToken string) (_ map[string][]string, err error) {
	defer derrors.Wrap(&err, "loadGHSAsByCVE")

	sas, err := ghsa.List(ctx, accessToken, time.Time{})
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
