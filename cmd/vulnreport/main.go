// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command vulnreport provides a tool for creating a YAML vulnerability report for
// x/vulndb.
package main

import (
	"context"
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
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/report"
)

var (
	localRepoPath = flag.String("local-cve-repo", "", "path to local repo, instead of cloning remote")
	issueRepo     = flag.String("issue-repo", "github.com/golang/vulndb", "repo to create issues in")
	githubToken   = flag.String("ghtoken", "", "GitHub access token (default: value of VULN_GITHUB_ACCESS_TOKEN)")
	skipSymbols   = flag.Bool("skip-symbols", false, "for lint and fix, don't load package for symbols checks")
	alwaysFixGHSA = flag.Bool("always-fix-ghsa", false, "for fix, always update GHSAs")
	updateIssue   = flag.Bool("up", false, "for commit, create a CL that updates (doesn't fix) the tracking bug")
	indent        = flag.Bool("indent", false, "for newcve, indent JSON output")
	closedOk      = flag.Bool("closed-ok", false, "for create & create-excluded, allow closed issues to be created")
	cpuprofile    = flag.String("cpuprofile", "", "write cpuprofile to file")
)

func main() {
	ctx := context.Background()
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: vulnreport [cmd] [filename.yaml]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  create [githubIssueNumber]: creates a new vulnerability YAML report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  create-excluded: creates and commits all open github issues marked as excluded\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  lint filename.yaml ...: lints vulnerability YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  cve filename.yaml ...: creates and saves CVE 5.0 record from the provided YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  cve4 filename.yaml ...: creates and prints CVE 4.0 record from the provided YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  fix filename.yaml ...: fixes and reformats YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  osv filename.yaml ...: converts YAMLS reports to OSV JSON and writes to data/osv\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  set-dates filename.yaml ...: sets PublishDate of YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  commit filename.yaml ...: creates new commits for YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  xref filename.yaml ...: prints cross references for YAML reports\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		log.Fatal("subcommand required")
	}

	if *githubToken == "" {
		*githubToken = os.Getenv("VULN_GITHUB_ACCESS_TOKEN")
	}

	var (
		args []string
		cmd  = flag.Arg(0)
	)
	if cmd != "create-excluded" {
		if flag.NArg() < 2 {
			flag.Usage()
			log.Fatal("not enough arguments")
		}
		args = flag.Args()[1:]
	}

	// Start CPU profiler.
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// setupCreate clones the CVEList repo and can be very slow,
	// so commands that require this functionality are separated from other
	// commands.
	if cmd == "create-excluded" || cmd == "create" {
		githubIDs, cfg, err := setupCreate(ctx, args)
		if err != nil {
			log.Fatal(err)
		}
		switch cmd {
		case "create-excluded":
			if err = createExcluded(ctx, cfg); err != nil {
				log.Fatal(err)
			}
		case "create":
			// Unlike commands below, create operates on github issue IDs
			// instead of filenames.
			for _, githubID := range githubIDs {
				if err := create(ctx, githubID, cfg); err != nil {
					fmt.Printf("skipped: %s\n", err)
				}
			}
		}
		return
	}

	ghsaClient := ghsa.NewClient(ctx, *githubToken)
	var cmdFunc func(string) error
	switch cmd {
	case "lint":
		cmdFunc = lint
	case "commit":
		cmdFunc = func(name string) error { return commit(ctx, name, ghsaClient) }
	case "cve":
		cmdFunc = func(name string) error { return cveCmd(ctx, name) }
	case "fix":
		cmdFunc = func(name string) error { return fix(ctx, name, ghsaClient) }
	case "osv":
		cmdFunc = osvCmd
	case "set-dates":
		repo, err := gitrepo.Open(ctx, ".")
		if err != nil {
			log.Fatal(err)
		}
		commitDates, err := gitrepo.AllCommitDates(repo, gitrepo.MainReference, report.YAMLDir)
		if err != nil {
			log.Fatal(err)
		}
		cmdFunc = func(name string) error { return setDates(name, commitDates) }
	case "xref":
		repo, err := gitrepo.Open(ctx, ".")
		if err != nil {
			log.Fatal(err)
		}
		_, existingByFile, err := report.GetAllExisting(repo)
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
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := cmdFunc(arg); err != nil {
			fmt.Fprintln(os.Stderr, err)
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
	repo            *git.Repository
	ghsaClient      *ghsa.Client
	issuesClient    *issues.Client
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
		log.Fatal(err)
	}
	existingByIssue, existingByFile, err := report.GetAllExisting(localRepo)
	if err != nil {
		return nil, nil, err
	}
	githubIDs, err := parseArgsToGithubIDs(args, existingByIssue)
	if err != nil {
		return nil, nil, err
	}
	repoPath := cvelistrepo.URL
	if *localRepoPath != "" {
		repoPath = *localRepoPath
	}
	repo, err := gitrepo.CloneOrOpen(ctx, repoPath)
	if err != nil {
		return nil, nil, err
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return nil, nil, err
	}
	return githubIDs, &createCfg{
		repo:            repo,
		issuesClient:    issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken}),
		ghsaClient:      ghsa.NewClient(ctx, *githubToken),
		existingByFile:  existingByFile,
		existingByIssue: existingByIssue,
		allowClosed:     *closedOk,
	}, nil
}

func createReport(ctx context.Context, cfg *createCfg, iss *issues.Issue) (r *report.Report, err error) {
	defer derrors.Wrap(&err, "createReport(%d)", iss.Number)
	parsed, err := parseGithubIssue(iss, cfg.allowClosed)
	if err != nil {
		return nil, err
	}
	if len(parsed.ghsas) == 0 && len(parsed.cves) > 0 {
		for _, cve := range parsed.cves {
			sas, err := cfg.ghsaClient.ListForCVE(ctx, cve)
			if err != nil {
				return nil, err
			}
			for _, sa := range sas {
				parsed.ghsas = append(parsed.ghsas, sa.ID)
			}
		}
		slices.Sort(parsed.ghsas)
		parsed.ghsas = slices.Compact(parsed.ghsas)
	}

	r, err = newReport(ctx, cfg, parsed)
	if err != nil {
		return nil, err
	}

	if parsed.excluded != "" {
		r = &report.Report{
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

	addTODOs(r)

	return r, nil
}

func create(ctx context.Context, issueNumber int, cfg *createCfg) (err error) {
	defer derrors.Wrap(&err, "create(%d)", issueNumber)
	// Get GitHub issue.
	iss, err := cfg.issuesClient.GetIssue(ctx, issueNumber)
	if err != nil {
		return err
	}

	r, err := createReport(ctx, cfg, iss)
	if err != nil {
		return err
	}

	filename := r.GetYAMLFilename(iss.NewGoID())
	if err := r.Write(filename); err != nil {
		return err
	}
	fmt.Println(filename)
	fmt.Print(xref(filename, r, cfg.existingByFile))
	return nil
}

func handleExcludedIssue(ctx context.Context, cfg *createCfg, iss *issues.Issue) (string, error) {
	r, err := createReport(ctx, cfg, iss)
	if err != nil {
		return "", err
	}
	r.Fix()

	filename := r.GetYAMLFilename(iss.NewGoID())
	if err := r.Write(filename); err != nil {
		return "", err
	}

	if lints := r.Lint(filename); len(lints) != 0 {
		return "", fmt.Errorf("lint errors %s: %v", filename, lints)
	}

	if err := irun("git", "add", filename); err != nil {
		return "", fmt.Errorf("git add %s: %v", filename, err)
	}
	return filename, nil
}

func createExcluded(ctx context.Context, cfg *createCfg) (err error) {
	defer derrors.Wrap(&err, "createExcluded()")
	excludedLabels := []string{"excluded: DEPENDENT_VULNERABILITY",
		"excluded: EFFECTIVELY_PRIVATE", "excluded: NOT_A_VULNERABILITY",
		"excluded: NOT_GO_CODE", "excluded: NOT_IMPORTABLE"}
	isses := []*issues.Issue{}
	stateOption := "open"
	if cfg.allowClosed {
		stateOption = "all"
	}
	for _, label := range excludedLabels {
		tempIssues, err :=
			cfg.issuesClient.GetIssues(ctx, issues.GetIssuesOptions{Labels: []string{label}, State: stateOption})
		if err != nil {
			return err
		}
		fmt.Printf("Found %d issues with label %s\n", len(tempIssues), label)
		isses = append(isses, tempIssues...)
	}

	var successfulIssNums, successfulGoIDs []string
	skipped := 0
	for _, iss := range isses {

		if _, exists := cfg.existingByIssue[iss.Number]; !cfg.allowClosed && exists {
			skipped++
			continue
		}
		filename, err := handleExcludedIssue(ctx, cfg, iss)
		if err != nil {
			fmt.Printf("skipped issue %d due to error: %v\n", iss.Number, err)
			skipped++
			continue
		}
		successfulIssNums = append(successfulIssNums, fmt.Sprintf("golang/vulndb#%d", iss.Number))
		successfulGoIDs = append(successfulGoIDs, report.GetGoIDFromFilename(filename))
	}
	fmt.Printf("Skipped %d issues\n", skipped)

	if len(successfulGoIDs) == 0 {
		fmt.Println("No files to commit, exiting")
		return nil
	}

	msg := fmt.Sprintf("%s: batch add %s\n\nFixes %s",
		report.ExcludedDir,
		strings.Join(successfulGoIDs, ", "),
		strings.Join(successfulIssNums, "\nFixes "))
	args := []string{"commit", "-m", msg, "-e"}

	if err := irun("git", args...); err != nil {
		return fmt.Errorf("git commit: %v", err)
	}

	return nil
}

func newReport(ctx context.Context, cfg *createCfg, parsed *parsedIssue) (*report.Report, error) {
	var r *report.Report
	switch {
	case len(parsed.ghsas) > 0:
		ghsa, err := cfg.ghsaClient.FetchGHSA(ctx, parsed.ghsas[0])
		if err != nil {
			return nil, err
		}
		r = report.GHSAToReport(ghsa, parsed.modulePath)
	case len(parsed.cves) > 0:
		cve, err := cvelistrepo.FetchCVE(ctx, cfg.repo, parsed.cves[0])
		if err != nil {
			return nil, err
		}
		r = report.CVEToReport(cve, parsed.modulePath)
	default:
		r = &report.Report{}
	}

	// Fill an any CVEs and GHSAs we found that may have been missed
	// in report creation.
	r.CVEs = append(r.CVEs, parsed.cves...)
	slices.Sort(r.CVEs)
	r.CVEs = slices.Compact(r.CVEs)

	r.GHSAs = append(r.GHSAs, parsed.ghsas...)
	slices.Sort(r.GHSAs)
	r.GHSAs = slices.Compact(r.GHSAs)

	return r, nil
}

type parsedIssue struct {
	modulePath string
	cves       []string
	ghsas      []string
	excluded   report.ExcludedReason
}

func parseGithubIssue(iss *issues.Issue, allowClosed bool) (*parsedIssue, error) {
	var parsed *parsedIssue = &parsedIssue{}

	if !allowClosed && iss.State == "closed" {
		return nil, errors.New("issue is closed")
	}

	// Parse labels for excluded and duplicate issues.
	for _, label := range iss.Labels {
		if strings.HasPrefix(label, "excluded: ") {
			if parsed.excluded == "" {
				parsed.excluded = report.ExcludedReason(strings.TrimPrefix(label, "excluded: "))
			} else {
				return nil, fmt.Errorf("issue has multiple excluded reasons")
			}
		}
		if label == "duplicate" {
			return nil, fmt.Errorf("duplicate issue")
		}
	}

	// Parse CVE and GHSA IDs from GitHub issue.
	parts := strings.Fields(iss.Title)
	for _, p := range parts {
		switch {
		case strings.HasSuffix(p, ":") && p != "x/vulndb:":
			parsed.modulePath = strings.TrimSuffix(p, ":")
			parsed.modulePath = strings.ReplaceAll(parsed.modulePath, "\"", "")
			parsed.modulePath = report.FindModuleFromPackage(parsed.modulePath)

		case strings.HasPrefix(p, "CVE"):
			parsed.cves = append(parsed.cves, strings.TrimSuffix(p, ","))
		case strings.HasPrefix(p, "GHSA"):
			parsed.ghsas = append(parsed.ghsas, strings.TrimSuffix(p, ","))
		}
	}

	if len(parsed.cves) == 0 && len(parsed.ghsas) == 0 {
		return nil, fmt.Errorf("%q has no CVE or GHSA IDs", iss.Title)
	}

	return parsed, nil
}

// xref returns cross-references for a report: Information about other reports
// for the same CVE, GHSA, or module.
func xref(rname string, r *report.Report, existingByFile map[string]*report.Report) string {
	out := &strings.Builder{}
	matches := report.XRef(r, existingByFile)
	delete(matches, rname)
	// This sorts as CVEs, GHSAs, and then modules.
	for _, fname := range sorted(maps.Keys(matches)) {
		for _, id := range sorted(matches[fname]) {
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
			if m.VulnerableAt == todo {
				p.SkipFix = todo + " [or remove to derive symbols]"
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

func fix(ctx context.Context, filename string, ghsaClient *ghsa.Client) (err error) {
	defer derrors.Wrap(&err, "fix(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if lints := r.Lint(filename); len(lints) > 0 {
		r.Fix()
	}

	// Adds a todo for a human. Currently outside of the scope of r.Fix()
	addSkipFixTodos(r)

	if !*skipSymbols {
		if err := checkReportSymbols(r); err != nil {
			return err
		}
	}
	if err := fixGHSAs(ctx, r, ghsaClient); err != nil {
		return err
	}
	// Write unconditionally in order to format.
	if err := r.Write(filename); err != nil {
		return err
	}
	goID := report.GetGoIDFromFilename(filename)
	if _, err := writeOSV(r, goID); err != nil {
		return err
	}
	if err := writeCVE(r, goID); err != nil {
		return err
	}
	return nil
}

// addSkipFixTodos adds a todo SkipFix to every package in an
// unexcluded module that does not give a VulnerableAt.
func addSkipFixTodos(r *report.Report) {
	if r.Excluded != "" {
		return
	}
	for _, m := range r.Modules {
		if m.VulnerableAt == "" {
			for _, p := range m.Packages {
				if p.SkipFix == "" {
					p.SkipFix = todo + " [or set vulnerable_at to derive symbols]"
				}
			}
		}
	}
}

func checkReportSymbols(r *report.Report) error {
	rc := newReportClient(r)

	for _, m := range r.Modules {
		if m.IsStdLib() {
			gover := runtime.Version()
			ver := semverForGoVersion(gover)
			// If some symbol is in the std library at a different version,
			// we may derive the wrong symbols for this package and other.
			// In this case, skip updating DerivedSymbols.
			affected := report.AffectedRanges(m.Versions).AffectsSemver(ver.V())
			if ver == "" || !affected {
				fmt.Fprintf(os.Stderr, "Current Go version %q is not in a vulnerable range, skipping symbol checks.\n", gover)
				continue
			}
			if ver != m.VulnerableAt {
				fmt.Fprintf(os.Stderr, "%v: WARNING: Go version %q does not match vulnerable_at version %q.\n", m.Module, ver, m.VulnerableAt)
			}
		}

		for _, p := range m.Packages {
			if p.SkipFix != "" {
				fmt.Fprintf(os.Stderr, "%v: skip_fix set, skipping symbol checks (reason: %q)\n", p.Package, p.SkipFix)
				continue
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
	defer derrors.Wrap(&err, "findExportedSymbols(%q, %q)", m.Module, p.Package)

	cleanup, err := changeToTempDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	if err := run("go", "mod", "init", "go.dev/_"); err != nil {
		return nil, err
	}
	if !m.IsStdLib() {
		pkgPathAndVersion := p.Package + "@" + m.VulnerableAt.V()
		if err := run("go", "get", pkgPathAndVersion); err != nil {
			return nil, err
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
	if m.IsStdLib() {
		if pm := pkgs[0].Module; pm != nil {
			return nil, fmt.Errorf("got module %v, expected nil", pm)
		}
	} else {
		if pm := pkgs[0].Module; pm == nil || pm.Path != m.Module {
			return nil, fmt.Errorf("got module %v, expected %s", pm, m.Module)
		}
	}

	if len(p.Symbols) == 0 {
		return nil, nil // no symbols to derive from. skip.
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

func osvCmd(filename string) (err error) {
	defer derrors.Wrap(&err, "osv(%q)", filename)
	r, err := report.ReadAndLint(filename)
	if err != nil {
		return err
	}
	osvFilename, err := writeOSV(r, report.GetGoIDFromFilename(filename))
	if err != nil {
		return err
	}
	fmt.Println(osvFilename)
	return nil
}

func writeOSV(r *report.Report, goID string) (string, error) {
	if r.Excluded == "" {
		entry := r.GenerateOSVEntry(goID, time.Time{})
		osvFilename := report.GetOSVFilename(goID)
		if err := database.WriteJSON(osvFilename, entry, true); err != nil {
			return "", err
		}
		return osvFilename, nil
	}
	return "", nil
}

func cveCmd(ctx context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "cve(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	return writeCVE(r, report.GetGoIDFromFilename(filename))
}

// writeCVE takes a report and its Go ID, converts the report
// into a JSON CVE5 record and writes it to data/cve/v5.
func writeCVE(r *report.Report, goID string) error {
	if r.CVEMetadata == nil {
		return nil
	}
	var cve *cveschema5.CVERecord
	var err error

	cvePath := report.GetCVEFilename(goID)
	if cve, err = r.ToCVE5(goID); err != nil {
		return err
	}
	if err = database.WriteJSON(cvePath, cve, true); err != nil {
		return err
	}

	return nil
}

var reportRegexp = regexp.MustCompile(`^(data/\w+)/(GO-\d\d\d\d-0*(\d+)\.yaml)$`)

func irun(name string, arg ...string) error {
	// Exec git commands rather than using go-git so as to run commit hooks
	// and give the user a chance to edit the commit message.
	cmd := exec.Command(name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func commit(ctx context.Context, filename string, ghsaClient *ghsa.Client) (err error) {
	defer derrors.Wrap(&err, "commit(%q)", filename)

	// Ignore errors. If anything is really wrong with the report, we'll
	// detect it on re-linting below.
	_ = fix(ctx, filename, ghsaClient)

	r, err := report.ReadAndLint(filename)
	if err != nil {
		return err
	}

	// Find all derived files (OSV and CVE).
	files := []string{filename}
	goID := report.GetGoIDFromFilename(filename)
	if r.Excluded == "" {
		files = append(files, report.GetOSVFilename(goID))
	}
	if r.CVEMetadata != nil {
		files = append(files, report.GetCVEFilename(goID))
	}

	// Add the files.
	addArgs := []string{"add"}
	addArgs = append(addArgs, files...)
	if err := irun("git", addArgs...); err != nil {
		fmt.Fprintf(os.Stderr, "git add: %v\n", err)
		return nil
	}

	// Commit the files, allowing the user to edit the default commit message.
	msg, err := newCommitMsg(r, filename)
	if err != nil {
		return err
	}
	commitArgs := []string{"commit", "-m", msg, "-e"}
	commitArgs = append(commitArgs, files...)
	if err := irun("git", commitArgs...); err != nil {
		fmt.Fprintf(os.Stderr, "git commit: %v\n", err)
		return nil
	}

	return nil
}

func newCommitMsg(r *report.Report, filepath string) (string, error) {
	folder, filename, issueID, err := report.ParseFilepath(filepath)
	if err != nil {
		return "", err
	}

	issueAction := "Fixes"
	fileAction := "add"
	if *updateIssue {
		fileAction = "update"
		issueAction = "Updates"
	}
	// For now, we need to manually publish the CVE record so the issue
	// should not be auto-closed on add.
	if r.CVEMetadata != nil {
		issueAction = "Updates"
	}

	return fmt.Sprintf(
		"%s: %s %s\n\nAliases: %s\n\n%s golang/vulndb#%d",
		folder, fileAction, filename, strings.Join(r.GetAliases(), ", "),
		issueAction, issueID), nil
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
func loadPackage(cfg *packages.Config, importPath string) (_ []*packages.Package, err error) {
	defer derrors.Wrap(&err, "loadPackage(%s)", importPath)

	cfg.Mode |= packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg.BuildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(build.Default.BuildTags, ","))}
	pkgs, err := packages.Load(cfg, importPath)
	if err != nil {
		return nil, err
	}

	if err := packageLoadingError(pkgs); err != nil {
		return nil, err
	}

	return pkgs, nil
}

// packageLoadingError returns an error summarizing packages.Package.Errors if there were any.
func packageLoadingError(pkgs []*packages.Package) error {
	pkgError := func(pkg *packages.Package) error {
		var msgs []string
		for _, err := range pkg.Errors {
			msgs = append(msgs, err.Error())
		}
		if len(msgs) == 0 {
			return nil
		}
		// Report a more helpful error message for the package if possible.
		for _, msg := range msgs {
			// cgo failure?
			if strings.Contains(msg, "could not import C (no metadata for C)") {
				const url = `https://github.com/golang/vulndb/blob/master/doc/triage.md#vulnreport-cgo-failures`
				return fmt.Errorf("package %s has a cgo error (install relevant C packages? %s)\nerrors:%s", pkg.PkgPath, url, strings.Join(msgs, "\n"))
			}
		}
		return fmt.Errorf("package %s had %d errors: %s", pkg.PkgPath, len(msgs), strings.Join(msgs, "\n"))
	}

	var paths []string
	var msgs []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		if err := pkgError(pkg); err != nil {
			paths = append(paths, pkg.PkgPath)
			msgs = append(msgs, err.Error())
		}
	})
	if len(msgs) == 0 {
		return nil // no errors
	}
	return fmt.Errorf("packages with errors: %s\nerrors:\n%s", strings.Join(paths, " "), strings.Join(msgs, "\n"))
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

// fixGHSAs replaces r.GHSAs with a sorted list of GitHub Security
// Advisory IDs that correspond to the CVEs.
func fixGHSAs(ctx context.Context, r *report.Report, ghsaClient *ghsa.Client) error {
	if len(r.GHSAs) > 0 && !*alwaysFixGHSA {
		return nil
	}
	m := map[string]struct{}{}
	for _, cid := range r.CVEs {
		sas, err := ghsaClient.ListForCVE(ctx, cid)
		if err != nil {
			return err
		}
		for _, sa := range sas {
			m[sa.ID] = struct{}{}
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
