// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command worker runs the vuln worker server.
// It can also be used to perform actions from the command line
// by providing a sub-command.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/exp/event"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

var (
	// Flags only for the command-line tool.
	localRepoPath = flag.String("local-cve-repo", "", "path to local repo, instead of cloning remote")
	force         = flag.Bool("force", false, "force an update or scan to happen")
	limit         = flag.Int("limit", 0,
		"limit on number of things to list or issues to create (0 means unlimited)")
	githubTokenFile = flag.String("ghtokenfile", "",
		"path to file containing GitHub access token (for creating issues)")
	knownModuleFile = flag.String("known-module-file", "", "file with list of all known modules")
)

// Config for both the server and the command-line tool.
var cfg worker.Config

func init() {
	flag.StringVar(&cfg.Project, "project", os.Getenv("GOOGLE_CLOUD_PROJECT"), "project ID (required)")
	flag.StringVar(&cfg.Namespace, "namespace", os.Getenv("VULN_WORKER_NAMESPACE"), "Firestore namespace (required)")
	flag.BoolVar(&cfg.UseErrorReporting, "report-errors", os.Getenv("VULN_WORKER_REPORT_ERRORS") == "true",
		"use the error reporting API")
	flag.StringVar(&cfg.IssueRepo, "issue-repo", os.Getenv("VULN_WORKER_ISSUE_REPO"), "repo to create issues in")
}

const pkgsiteURL = "https://pkg.go.dev"

func main() {
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage:")
		fmt.Fprintln(out, "worker FLAGS")
		fmt.Fprintln(out, "  run as a server, listening at the PORT env var")
		fmt.Fprintln(out, "worker FLAGS SUBCOMMAND ...")
		fmt.Fprintln(out, "  run as a command-line tool, executing SUBCOMMAND")
		fmt.Fprintln(out, "  subcommands:")
		fmt.Fprintln(out, "    update COMMIT: perform an update operation")
		fmt.Fprintln(out, "    list-updates: display info about update operations")
		fmt.Fprintln(out, "    list-cves TRIAGE_STATE: display info about CVE records")
		fmt.Fprintln(out, "    create-issues: create issues for CVEs that need them")
		fmt.Fprintln(out, "    show ID1 ID2 ...: display CVE records")
		fmt.Fprintln(out, "flags:")
		flag.PrintDefaults()
	}

	flag.Parse()
	if *githubTokenFile != "" {
		data, err := os.ReadFile(*githubTokenFile)
		if err != nil {
			die("%v", err)
		}
		cfg.GitHubAccessToken = strings.TrimSpace(string(data))
	} else {
		cfg.GitHubAccessToken = os.Getenv("VULN_GITHUB_ACCESS_TOKEN")
	}
	if err := cfg.Validate(); err != nil {
		dieWithUsage("%v", err)
	}

	ctx := event.WithExporter(context.Background(),
		event.NewExporter(log.NewLineHandler(os.Stderr), nil))
	if img := os.Getenv("DOCKER_IMAGE"); img != "" {
		log.Infof(ctx, "running in docker image %s", img)
	}
	log.Infof(ctx, "config: project=%s, namespace=%s, issueRepo=%s", cfg.Project, cfg.Namespace, cfg.IssueRepo)

	var err error
	cfg.Store, err = store.NewFireStore(ctx, cfg.Project, cfg.Namespace, "")
	if err != nil {
		die("firestore: %v", err)
	}
	if flag.NArg() > 0 {
		err = runCommandLine(ctx)
	} else {
		err = runServer(ctx)
	}
	if err != nil {
		dieWithUsage("%v", err)
	}
}

func runServer(ctx context.Context) error {
	if os.Getenv("PORT") == "" {
		return errors.New("need PORT")
	}
	if _, err := worker.NewServer(ctx, cfg); err != nil {
		return err
	}
	addr := ":" + os.Getenv("PORT")
	log.Infof(ctx, "Listening on addr %s", addr)
	return fmt.Errorf("listening: %v", http.ListenAndServe(addr, nil))
}

const timeFormat = "2006/01/02 15:04:05"

func runCommandLine(ctx context.Context) error {
	switch flag.Arg(0) {
	case "list-updates":
		return listUpdatesCommand(ctx)
	case "list-cves":
		return listCVEsCommand(ctx, flag.Arg(1))
	case "update":
		if flag.NArg() != 2 {
			return errors.New("usage: update COMMIT")
		}
		return updateCommand(ctx, flag.Arg(1))
	case "create-issues":
		return createIssuesCommand(ctx)
	case "show":
		return showCommand(ctx, flag.Args()[1:])
	default:
		return fmt.Errorf("unknown command: %q", flag.Arg(1))
	}
}

func listUpdatesCommand(ctx context.Context) error {
	recs, err := cfg.Store.ListCommitUpdateRecords(ctx, 0)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 1, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "Start\tEnd\tCommit\tID\tCVEs Processed\n")
	for i, r := range recs {
		if *limit > 0 && i >= *limit {
			break
		}
		endTime := "unfinished"
		if !r.EndedAt.IsZero() {
			endTime = r.EndedAt.In(time.Local).Format(timeFormat)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d/%d (added %d, modified %d)\n",
			r.StartedAt.In(time.Local).Format(timeFormat),
			endTime,
			r.CommitHash,
			r.ID,
			r.NumProcessed, r.NumTotal, r.NumAdded, r.NumModified)
	}
	return tw.Flush()
}

func listCVEsCommand(ctx context.Context, triageState string) error {
	ts := store.TriageState(triageState)
	if err := ts.Validate(); err != nil {
		return err
	}
	crs, err := cfg.Store.ListCVERecordsWithTriageState(ctx, ts)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 1, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tCVEState\tCommit\tReason\tModule\tIssue\tIssue Created\n")
	for i, r := range crs {
		if *limit > 0 && i >= *limit {
			break
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.CVEState, r.CommitHash, r.TriageStateReason, r.Module, r.IssueReference, worker.FormatTime(r.IssueCreatedAt))
	}
	return tw.Flush()
}

func updateCommand(ctx context.Context, commitHash string) error {
	repoPath := cvelistrepo.URLv4
	if *localRepoPath != "" {
		repoPath = *localRepoPath
	}
	if *knownModuleFile != "" {
		if err := populateKnownModules(*knownModuleFile); err != nil {
			return err
		}
	}
	err := worker.UpdateCVEsAtCommit(ctx, repoPath, commitHash, cfg.Store, pkgsiteURL, *force)
	if cerr := new(worker.CheckUpdateError); errors.As(err, &cerr) {
		return fmt.Errorf("%w; use -force to override", cerr)
	}
	if err != nil {
		return err
	}
	if cfg.GitHubAccessToken == "" {
		fmt.Printf("Missing GitHub access token; not updating GH security advisories.\n")
		return nil
	}
	ghsaClient := ghsa.NewClient(ctx, cfg.GitHubAccessToken)
	listSAs := func(ctx context.Context, since time.Time) ([]*ghsa.SecurityAdvisory, error) {
		return ghsaClient.List(ctx, since)
	}
	_, err = worker.UpdateGHSAs(ctx, listSAs, cfg.Store)
	return err
}

func populateKnownModules(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	var mods []string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		mods = append(mods, line)
	}
	if err := scan.Err(); err != nil {
		return err
	}
	worker.SetKnownModules(mods)
	fmt.Printf("set %d known modules\n", len(mods))
	return nil
}

func createIssuesCommand(ctx context.Context) error {
	if cfg.IssueRepo == "" {
		return errors.New("need -issue-repo")
	}
	if cfg.GitHubAccessToken == "" {
		return errors.New("need -ghtokenfile")
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(cfg.IssueRepo)
	if err != nil {
		return err
	}
	client := issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: cfg.GitHubAccessToken})
	repo, err := gitrepo.Clone(ctx, "https://github.com/golang/vulndb")
	if err != nil {
		return err
	}
	_, allReports, err := report.All(repo)
	if err != nil {
		return err
	}
	pc := proxy.NewDefaultClient()
	return worker.CreateIssues(ctx, cfg.Store, client, pc, allReports, *limit)
}

func showCommand(ctx context.Context, ids []string) error {
	for _, id := range ids {
		r, err := cfg.Store.GetCVERecord(ctx, id)
		if err != nil {
			return err
		}
		if r == nil {
			fmt.Printf("%s not found\n", id)
		} else {
			// Display as JSON because it's an easy way to get nice formatting.
			j, err := json.MarshalIndent(r, "", "\t")
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", j)
		}
	}
	return nil
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

func dieWithUsage(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	fmt.Fprintln(os.Stderr)
	flag.Usage()
	os.Exit(1)
}
