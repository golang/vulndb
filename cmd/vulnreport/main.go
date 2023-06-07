// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command vulnreport provides a tool for creating a YAML vulnerability report for
// x/vulndb.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/build"
	"go/types"
	"io"
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
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
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
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var (
	localRepoPath = flag.String("local-cve-repo", "", "path to local repo, instead of cloning remote")
	issueRepo     = flag.String("issue-repo", "github.com/golang/vulndb", "repo to create issues in")
	githubToken   = flag.String("ghtoken", "", "GitHub access token (default: value of VULN_GITHUB_ACCESS_TOKEN)")
	skipSymbols   = flag.Bool("skip-symbols", false, "for lint and fix, don't load package for symbols checks")
	skipGHSA      = flag.Bool("skip-ghsa", false, "for fix, skip adding new GHSAs")
	updateIssue   = flag.Bool("up", false, "for commit, create a CL that updates (doesn't fix) the tracking bug")
	closedOk      = flag.Bool("closed-ok", false, "for create & create-excluded, allow closed issues to be created")
	cpuprofile    = flag.String("cpuprofile", "", "write cpuprofile to file")
	quiet         = flag.Bool("q", false, "quiet mode (suppress info logs)")
)

var (
	infolog *log.Logger
	outlog  *log.Logger
	warnlog *log.Logger
	errlog  *log.Logger
)

func init() {
	infolog = log.New(os.Stdout, "info: ", 0)
	outlog = log.New(os.Stdout, "", 0)
	warnlog = log.New(os.Stderr, "WARNING: ", 0)
	errlog = log.New(os.Stderr, "ERROR: ", 0)
}

func main() {
	ctx := context.Background()
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: vulnreport [cmd] [filename.yaml]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  create [githubIssueNumber]: creates a new vulnerability YAML report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  create-excluded: creates and commits all open github issues marked as excluded\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  lint filename.yaml ...: lints vulnerability YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  cve filename.yaml ...: creates and saves CVE 5.0 record from the provided YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  fix filename.yaml ...: fixes and reformats YAML reports\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  osv filename.yaml ...: converts YAML reports to OSV JSON and writes to data/osv\n")
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

	if *quiet {
		infolog = log.New(io.Discard, "", 0)
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
		_ = pprof.StartCPUProfile(f)
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
					errlog.Println(err)
				}
			}
		}
		return
	}

	ghsaClient := ghsa.NewClient(ctx, *githubToken)
	var cmdFunc func(context.Context, string) error
	switch cmd {
	case "lint":
		cmdFunc = lint
	case "commit":
		cmdFunc = func(ctx context.Context, name string) error { return commit(ctx, name, ghsaClient) }
	case "cve":
		cmdFunc = func(ctx context.Context, name string) error { return cveCmd(ctx, name) }
	case "fix":
		cmdFunc = func(ctx context.Context, name string) error { return fix(ctx, name, ghsaClient) }
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
		cmdFunc = func(ctx context.Context, name string) error { return setDates(ctx, name, commitDates) }
	case "xref":
		repo, err := gitrepo.Open(ctx, ".")
		if err != nil {
			log.Fatal(err)
		}
		_, existingByFile, err := report.All(repo)
		if err != nil {
			log.Fatal(err)
		}
		cmdFunc = func(ctx context.Context, name string) error {
			r, err := report.Read(name)
			if err != nil {
				return err
			}
			outlog.Println(name)
			outlog.Println(xref(name, r, existingByFile))
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
			errlog.Println(err)
			continue
		}
		if err := cmdFunc(ctx, arg); err != nil {
			errlog.Println(err)
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
		return "", fmt.Errorf("%s is not a valid filename or issue ID with existing report: %w", arg, err)
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
	ghsaClient      *ghsa.Client
	issuesClient    *issues.Client
	existingByFile  map[string]*report.Report
	existingByIssue map[int]*report.Report
	allowClosed     bool
}

var (
	once    sync.Once
	cveRepo *git.Repository
)

func loadCVERepo(ctx context.Context) *git.Repository {
	// Loading the CVE git repo takes a while, so do it on demand only.
	once.Do(func() {
		infolog.Println("cloning CVE repo (this takes a while)")
		repoPath := cvelistrepo.URL
		if *localRepoPath != "" {
			repoPath = *localRepoPath
		}
		var err error
		cveRepo, err = gitrepo.CloneOrOpen(ctx, repoPath)
		if err != nil {
			log.Fatal(err)
		}
	})
	return cveRepo
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
	id := iss.NewGoID()
	infolog.Printf("creating report %s", id)

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
	r.ID = id
	return r, nil
}

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
	infolog.Print(xref(filename, r, cfg.existingByFile))
	return nil
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
		cve, err := cvelistrepo.FetchCVE(ctx, loadCVERepo(ctx), parsed.cves[0])
		if err != nil {
			return nil, err
		}
		r = report.CVEToReport(cve, parsed.modulePath)
	default:
		r = &report.Report{}
	}

	if err := addGHSAs(ctx, r, cfg.ghsaClient); err != nil {
		return nil, err
	}

	// Fill an any CVEs and GHSAs we found that may have been missed
	// in report creation.
	if r.CVEMetadata == nil {
		r.CVEs = dedupeAndSort(append(r.CVEs, parsed.cves...))
	}
	r.GHSAs = dedupeAndSort(append(r.GHSAs, parsed.ghsas...))

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

	// Parse elements from GitHub issue title.
	parts := strings.Fields(iss.Title)
	for _, p := range parts {
		switch {
		case p == "x/vulndb:":
			continue
		case strings.HasSuffix(p, ":"):
			// Remove backslashes.
			path := strings.ReplaceAll(strings.TrimSuffix(p, ":"), "\"", "")
			// Find the underlying module if this is a package path.
			if module := proxy.FindModule(parsed.modulePath); module != "" {
				parsed.modulePath = module
			} else {
				parsed.modulePath = path
			}
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
			m.VulnerableAt = todo + " [and/or add skip_fix to skip a package]"
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
	if r.Summary == "" {
		r.Summary = "TODO: add a short (one phrase) summary of the form '<Problem> in <module>(s)'"
	}
	if r.Description == "" {
		r.Description = todo
	}
	if len(r.Credits) == 0 {
		r.Credits = []string{todo}
	}
	if len(r.CVEs) == 0 {
		r.CVEs = []string{todo}
	}
	addReferenceTODOs(r)
}

// hasUnaddressedTodos returns true if report has any unaddressed todos in the
// report, i.e. starts with "TODO:".
func hasUnaddressedTodos(r *report.Report) bool {
	is := func(s string) bool { return strings.HasPrefix(s, "TODO:") }
	any := func(ss []string) bool { return slices.IndexFunc(ss, is) >= 0 }

	if is(string(r.Excluded)) {
		return true
	}
	for _, m := range r.Modules {
		if is(m.Module) {
			return true
		}
		for _, v := range m.Versions {
			if is(string(v.Introduced)) {
				return true
			}
			if is(string(v.Fixed)) {
				return true
			}
		}
		if is(string(m.VulnerableAt)) {
			return true
		}
		for _, p := range m.Packages {
			if is(p.Package) || is(p.SkipFix) || any(p.Symbols) || any(p.DerivedSymbols) {
				return true
			}
		}
	}
	for _, ref := range r.References {
		if is(ref.URL) {
			return true
		}
	}
	if any(r.CVEs) || any(r.GHSAs) {
		return true
	}
	return is(r.Summary) || is(r.Description) || any(r.Credits)
}

// addReferenceTODOs adds a TODO for each reference type not already present
// in the report.
func addReferenceTODOs(r *report.Report) {
	todos := []*report.Reference{
		{Type: osv.ReferenceTypeAdvisory, URL: "TODO: canonical security advisory"},
		{Type: osv.ReferenceTypeArticle, URL: "TODO: article or blog post"},
		{Type: osv.ReferenceTypeReport, URL: "TODO: issue tracker link"},
		{Type: osv.ReferenceTypeFix, URL: "TODO: PR or commit"},
		{Type: osv.ReferenceTypeWeb, URL: "TODO: web page of some unspecified kind"}}

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

func lint(ctx context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "lint(%q)", filename)
	infolog.Printf("lint %s\n", filename)

	_, err = report.ReadAndLint(filename)
	return err
}

func fix(ctx context.Context, filename string, ghsaClient *ghsa.Client) (err error) {
	defer derrors.Wrap(&err, "fix(%q)", filename)
	infolog.Printf("fix %s\n", filename)

	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if err := r.CheckFilename(filename); err != nil {
		return err
	}
	if lints := r.Lint(); len(lints) > 0 {
		r.Fix()
	}
	if lints := r.Lint(); len(lints) > 0 {
		warnlog.Printf("%s still has lint errors after fix:\n\t- %s", filename, strings.Join(lints, "\n\t- "))
	}

	if !*skipSymbols {
		if err := checkReportSymbols(r); err != nil {
			return err
		}
	}
	if !*skipGHSA {
		if err := addGHSAs(ctx, r, ghsaClient); err != nil {
			return err
		}
	}

	// Write unconditionally in order to format.
	if err := r.Write(filename); err != nil {
		return err
	}

	if !r.IsExcluded() {
		if err := writeOSV(r); err != nil {
			return err
		}
	}

	if r.CVEMetadata != nil {
		if err := writeCVE(r); err != nil {
			return err
		}
	}

	return nil
}

func checkReportSymbols(r *report.Report) error {
	if r.IsExcluded() {
		infolog.Printf("%s is excluded, skipping symbol checks\n", r.ID)
		return nil
	}
	for _, m := range r.Modules {
		if m.IsFirstParty() {
			gover := runtime.Version()
			ver := semverForGoVersion(gover)
			// If some symbol is in the std library at a different version,
			// we may derive the wrong symbols for this package and other.
			// In this case, skip updating DerivedSymbols.
			affected, err := osvutils.AffectsSemver(report.AffectedRanges(m.Versions), ver)
			if err != nil {
				return err
			}
			if ver == "" || !affected {
				warnlog.Printf("current Go version %q is not in a vulnerable range, skipping symbol checks\n", gover)
				continue
			}
			if ver != m.VulnerableAt {
				warnlog.Printf("%v: Go version %q does not match vulnerable_at version %q\n", m.Module, ver, m.VulnerableAt)
			}
		}

		for _, p := range m.Packages {
			if p.SkipFix != "" {
				infolog.Printf("%v: skip_fix set, skipping symbol checks (reason: %q)\n", p.Package, p.SkipFix)
				continue
			}
			syms, err := findExportedSymbols(m, p)
			if err != nil {
				return err
			}
			p.DerivedSymbols = syms
		}
	}

	return nil
}

func findExportedSymbols(m *report.Module, p *report.Package) (_ []string, err error) {
	defer derrors.Wrap(&err, "findExportedSymbols(%q, %q)", m.Module, p.Package)

	cleanup, err := changeToTempDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// This procedure was developed through trial and error finding a way
	// to load symbols for GO-2023-1549, which has a dependency tree that
	// includes go.mod files that reference v0.0.0 versions which do not exist.
	//
	// Create an empty go.mod.
	if err := run("go", "mod", "init", "go.dev/_"); err != nil {
		return nil, err
	}
	if !m.IsFirstParty() {
		// Require the module we're interested in at the vulnerable_at version.
		if err := run("go", "mod", "edit", "-require", m.Module+"@v"+m.VulnerableAt); err != nil {
			return nil, err
		}
		for _, req := range m.VulnerableAtRequires {
			if err := run("go", "mod", "edit", "-require", req); err != nil {
				return nil, err
			}
		}
		// Create a package that imports the package we're interested in.
		var content bytes.Buffer
		fmt.Fprintf(&content, "package p\n")
		fmt.Fprintf(&content, "import _ %q\n", p.Package)
		for _, req := range m.VulnerableAtRequires {
			pkg, _, _ := strings.Cut(req, "@")
			fmt.Fprintf(&content, "import _ %q", pkg)
		}
		if err := os.WriteFile("p.go", content.Bytes(), 0666); err != nil {
			return nil, err
		}
	}
	// Run go mod tidy.
	if err := run("go", "mod", "tidy"); err != nil {
		return nil, err
	}

	pkg, err := loadPackage(&packages.Config{}, p.Package)
	if err != nil {
		return nil, err
	}
	// First package should match package path and module.
	if pkg.PkgPath != p.Package {
		return nil, fmt.Errorf("first package had import path %s, wanted %s", pkg.PkgPath, p.Package)
	}
	if m.IsFirstParty() {
		if pm := pkg.Module; pm != nil {
			return nil, fmt.Errorf("got module %v, expected nil", pm)
		}
	} else {
		if pm := pkg.Module; pm == nil || pm.Path != m.Module {
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
			n, ok := pkg.Types.Scope().Lookup(typ).(*types.TypeName)
			if !ok {
				errlog.Printf("%v: type not found\n", typ)
				continue
			}
			m, _, _ := types.LookupFieldOrMethod(n.Type(), true, pkg.Types, method)
			if m == nil {
				errlog.Printf("%v: method not found\n", sym)
			}
		} else {
			_, ok := pkg.Types.Scope().Lookup(typ).(*types.Func)
			if !ok {
				errlog.Printf("%v: func not found\n", typ)
			}
		}
	}

	newsyms, err := exportedFunctions(pkg, m)
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

func osvCmd(ctx context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "osv(%q)", filename)
	r, err := report.ReadAndLint(filename)
	if err != nil {
		return err
	}
	if !r.IsExcluded() {
		if err := writeOSV(r); err != nil {
			return err
		}
		outlog.Println(r.OSVFilename())
	}
	return nil
}

func writeOSV(r *report.Report) error {
	return database.WriteJSON(r.OSVFilename(), r.ToOSV(time.Time{}), true)
}

func cveCmd(ctx context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "cve(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if r.CVEMetadata != nil {
		if err := writeCVE(r); err != nil {
			return err
		}
		outlog.Println(r.CVEFilename())
	}
	return nil
}

// writeCVE converts a report to JSON CVE5 record and writes it to
// data/cve/v5.
func writeCVE(r *report.Report) error {
	cve, err := r.ToCVE5()
	if err != nil {
		return err
	}
	return database.WriteJSON(r.CVEFilename(), cve, true)
}

func commit(ctx context.Context, filename string, ghsaClient *ghsa.Client) (err error) {
	defer derrors.Wrap(&err, "commit(%q)", filename)

	// Clean up the report file and lint the result.
	// Stop if there any problems.
	if err := fix(ctx, filename, ghsaClient); err != nil {
		return err
	}
	r, err := report.ReadAndLint(filename)
	if err != nil {
		return err
	}
	if hasUnaddressedTodos(r) {
		// Check after fix() as it can add new TODOs.
		return fmt.Errorf("file %q has unaddressed %q fields", filename, "TODO:")
	}

	// Find all derived files (OSV and CVE).
	files := []string{filename}
	if r.Excluded == "" {
		files = append(files, r.OSVFilename())
	}
	if r.CVEMetadata != nil {
		files = append(files, r.CVEFilename())
	}

	// Add the files to git.
	if err := gitAdd(files...); err != nil {
		return err
	}

	// Commit the files, allowing the user to edit the default commit message.
	msg, err := newCommitMsg(r)
	if err != nil {
		return err
	}
	return gitCommit(msg, files...)
}

func newCommitMsg(r *report.Report) (string, error) {
	f, err := r.YAMLFilename()
	if err != nil {
		return "", err
	}

	folder, filename, issueID, err := report.ParseFilepath(f)
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
		folder, fileAction, filename, strings.Join(r.Aliases(), ", "),
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
func semverForGoVersion(v string) string {
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
	return version
}

// loadPackage loads the package at the given import path, with enough
// information for constructing a call graph.
func loadPackage(cfg *packages.Config, importPath string) (_ *packages.Package, err error) {
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

	if len(pkgs) == 0 {
		return nil, errors.New("no packages found")
	}
	if len(pkgs) > 1 {
		return nil, fmt.Errorf("multiple (%d) packages found for import path %s", len(pkgs), importPath)
	}

	return pkgs[0], nil
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
		errlog.Println(string(out))
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
func setDates(ctx context.Context, filename string, dates map[string]gitrepo.Dates) (err error) {
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

func dedupeAndSort[T constraints.Ordered](s []T) []T {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

// addGHSAs adds any missing GHSAs that correspond to the CVEs in the report.
func addGHSAs(ctx context.Context, r *report.Report, ghsaClient *ghsa.Client) error {
	ghsas := r.GHSAs
	for _, cve := range r.AllCVEs() {
		sas, err := ghsaClient.ListForCVE(ctx, cve)
		if err != nil {
			return err
		}
		for _, sa := range sas {
			ghsas = append(ghsas, sa.ID)
		}
	}
	r.GHSAs = dedupeAndSort(ghsas)
	return nil
}
