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
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/cveclient"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/genericosv"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

var (
	issueRepo   = flag.String("issue-repo", "github.com/golang/vulndb", "repo to create issues in")
	githubToken = flag.String("ghtoken", "", "GitHub access token (default: value of VULN_GITHUB_ACCESS_TOKEN)")
	skipSymbols = flag.Bool("skip-symbols", false, "for lint and fix, don't load package for symbols checks")
	skipAlias   = flag.Bool("skip-alias", false, "for fix, skip adding new GHSAs and CVEs")
	graphQL     = flag.Bool("graphql", false, "for create, fetch GHSAs from the Github GraphQL API instead of the OSV database")
	preferCVE   = flag.Bool("cve", false, "for create, prefer CVEs over GHSAs as canonical source")
	updateIssue = flag.Bool("up", false, "for commit, create a CL that updates (doesn't fix) the tracking bug")
	closedOk    = flag.Bool("closed-ok", false, "for create & create-excluded, allow closed issues to be created")
	cpuprofile  = flag.String("cpuprofile", "", "write cpuprofile to file")
	quiet       = flag.Bool("q", false, "quiet mode (suppress info logs)")
	force       = flag.Bool("f", false, "for fix, force Fix to run even if there are no lint errors")
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
		fmt.Fprintf(flag.CommandLine.Output(), "  suggest filename.yaml ...: (EXPERIMENTAL) use AI to suggest summary and description for YAML reports\n")
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
	pc := proxy.NewDefaultClient()
	var cmdFunc func(context.Context, string) error
	switch cmd {
	case "lint":
		cmdFunc = func(ctx context.Context, name string) error { return lint(ctx, name, pc) }
	case "suggest":
		cmdFunc = func(ctx context.Context, name string) error { return suggest(ctx, name) }
	case "commit":
		cmdFunc = func(ctx context.Context, name string) error { return commit(ctx, name, ghsaClient, pc, *force) }
	case "cve":
		cmdFunc = func(ctx context.Context, name string) error { return cveCmd(ctx, name) }
	case "fix":
		cmdFunc = func(ctx context.Context, name string) error { return fix(ctx, name, ghsaClient, pc, *force) }
	case "osv":
		cmdFunc = func(ctx context.Context, name string) error { return osvCmd(ctx, name, pc) }
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
		infolog.Printf("no alias found, creating empty report %s", parsed.id)
		r = &report.Report{ID: parsed.id}
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

// pickBestAlias returns the "best" alias in the list.
// By default, it prefers the first GHSA in the list, followed by the first CVE in the list
// (if no GHSA is present).
// If "preferCVE" is true, it prefers CVEs instead.
// If no GHSAs or CVEs are present, it returns ("", false).
func pickBestAlias(aliases []string, preferCVE bool) (_ string, ok bool) {
	firstChoice := ghsa.IsGHSA
	secondChoice := cveschema5.IsCVE
	if preferCVE {
		firstChoice, secondChoice = secondChoice, firstChoice
	}
	for _, alias := range aliases {
		if firstChoice(alias) {
			return alias, true
		}
	}
	for _, alias := range aliases {
		if secondChoice(alias) {
			return alias, true
		}
	}
	return "", false
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

type parsedIssue struct {
	id         string
	modulePath string
	aliases    []string
	excluded   report.ExcludedReason
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
		case strings.HasSuffix(p, ":"):
			// Remove backslashes.
			parsed.modulePath = strings.ReplaceAll(strings.TrimSuffix(p, ":"), "\"", "")
			// Find the underlying module if this is a package path.
			if module, err := pc.FindModule(parsed.modulePath); err == nil { // no error
				parsed.modulePath = module
			}
		case cveschema5.IsCVE(p) || ghsa.IsGHSA(p):
			parsed.aliases = append(parsed.aliases, strings.TrimSuffix(p, ","))
		}
	}

	if len(parsed.aliases) == 0 {
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
	return is(r.Summary.String()) || is(r.Description.String()) || any(r.Credits)
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

func lint(_ context.Context, filename string, pc *proxy.Client) (err error) {
	defer derrors.Wrap(&err, "lint(%q)", filename)
	infolog.Printf("lint %s\n", filename)

	_, err = report.ReadAndLint(filename, pc)
	return err
}

func fix(ctx context.Context, filename string, ghsaClient *ghsa.Client, pc *proxy.Client, force bool) (err error) {
	defer derrors.Wrap(&err, "fix(%q)", filename)
	infolog.Printf("fix %s\n", filename)

	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if err := r.CheckFilename(filename); err != nil {
		return err
	}

	// We may make partial progress on fixing a report, so write the
	// report even if a fatal error occurs somewhere.
	defer func() {
		if err := r.Write(filename); err != nil {
			errlog.Println(err)
		}
	}()

	if lints := r.Lint(pc); force || len(lints) > 0 {
		r.Fix(pc)
	}
	if lints := r.Lint(pc); len(lints) > 0 {
		warnlog.Printf("%s still has lint errors after fix:\n\t- %s", filename, strings.Join(lints, "\n\t- "))
	}

	if !*skipSymbols {
		infolog.Printf("%s: checking packages and symbols (use -skip-symbols to skip this)", r.ID)
		if err := checkReportSymbols(r); err != nil {
			return err
		}
	}
	if !*skipAlias {
		infolog.Printf("%s: checking for missing GHSAs and CVEs (use -skip-alias to skip this)", r.ID)
		if added := addMissingAliases(ctx, r, ghsaClient); added > 0 {
			infolog.Printf("%s: added %d missing aliases", r.ID, added)
		}
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
				warnlog.Printf("%s: current Go version %q is not in a vulnerable range, skipping symbol checks for module %s\n", r.ID, gover, m.Module)
				continue
			}
			if ver != m.VulnerableAt {
				warnlog.Printf("%s: current Go version %q does not match vulnerable_at version (%s) for module %s\n", r.ID, ver, m.VulnerableAt, m.Module)
			}
		}

		for _, p := range m.Packages {
			if p.SkipFix != "" {
				infolog.Printf("%s: skipping symbol checks for package %s (reason: %q)\n", r.ID, p.Package, p.SkipFix)
				continue
			}
			syms, err := symbols.Exported(m, p, errlog)
			if err != nil {
				return fmt.Errorf("package %s: %w", p.Package, err)
			}
			if !cmp.Equal(syms, p.DerivedSymbols) {
				p.DerivedSymbols = syms
				infolog.Printf("%s: updated derived symbols for package %s\n", r.ID, p.Package)
			}
		}
	}

	return nil
}

func osvCmd(_ context.Context, filename string, pc *proxy.Client) (err error) {
	defer derrors.Wrap(&err, "osv(%q)", filename)

	r, err := report.ReadAndLint(filename, pc)
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

func cveCmd(_ context.Context, filename string) (err error) {
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

func commit(ctx context.Context, filename string, ghsaClient *ghsa.Client, pc *proxy.Client, force bool) (err error) {
	defer derrors.Wrap(&err, "commit(%q)", filename)

	// Clean up the report file and lint the result.
	// Stop if there any problems.
	if err := fix(ctx, filename, ghsaClient, pc, force); err != nil {
		return err
	}
	r, err := report.ReadAndLint(filename, pc)
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
func setDates(_ context.Context, filename string, dates map[string]gitrepo.Dates) (err error) {
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
