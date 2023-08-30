// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command issue provides a tool for creating an issue on the x/vulndb issue
// tracker.
//
// This is used to creating missing issues that were not created by the vulndb
// worker for various reasons.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"golang.org/x/vulndb/internal"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker"
)

var (
	githubToken = flag.String("ghtoken", os.Getenv("VULN_GITHUB_ACCESS_TOKEN"), "GitHub access token")
	issueRepo   = flag.String("issue-repo", "github.com/golang/vulndb", "repo to create issues in")
)

func main() {
	ctx := context.Background()
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: issue [cmd] [filename]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "	triage: [filename]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "	excluded: [filename]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}
	cmd := flag.Args()[0]
	filename := flag.Args()[1]
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		log.Fatal(err)
	}
	c := issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken})
	ghsaClient := ghsa.NewClient(ctx, *githubToken)
	pc := proxy.NewDefaultClient()
	switch cmd {
	case "triage":
		err = createIssueToTriage(ctx, c, ghsaClient, pc, filename)
	case "excluded":
		err = createExcluded(ctx, c, ghsaClient, pc, filename)
	default:
		err = fmt.Errorf("unsupported command: %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func createIssueToTriage(ctx context.Context, c *issues.Client, ghsaClient *ghsa.Client, pc *proxy.Client, filename string) (err error) {
	aliases, err := parseAliases(filename)
	if err != nil {
		return err
	}
	for _, alias := range aliases {
		if err := constructIssue(ctx, c, ghsaClient, pc, alias, []string{"NeedsTriage"}); err != nil {
			return err
		}
	}
	return nil
}

func createExcluded(ctx context.Context, c *issues.Client, ghsaClient *ghsa.Client, pc *proxy.Client, filename string) (err error) {
	records, err := parseExcluded(filename)
	if err != nil {
		return err
	}
	for _, r := range records {
		if err := constructIssue(ctx, c, ghsaClient, pc, r.identifier, []string{fmt.Sprintf("excluded: %s", r.category)}); err != nil {
			return err
		}
	}
	return nil
}

func constructIssue(ctx context.Context, c *issues.Client, ghsaClient *ghsa.Client, pc *proxy.Client, alias string, labels []string) (err error) {
	var ghsas []*ghsa.SecurityAdvisory
	if strings.HasPrefix(alias, "GHSA") {
		sa, err := ghsaClient.FetchGHSA(ctx, alias)
		if err != nil {
			return err
		}
		ghsas = append(ghsas, sa)
	} else if strings.HasPrefix(alias, "CVE") {
		ghsas, err = ghsaClient.ListForCVE(ctx, alias)
		if err != nil {
			return err
		}
		if len(ghsas) == 0 {
			fmt.Printf("%q does not have a GHSA\n", alias)
			return nil
		}
		if len(ghsas) > 1 {
			fmt.Printf("%q has multiple GHSAs\n", alias)
		}
	}

	// Only include the first package path in the issue.
	pkgPath := "unknown"
	if len(ghsas[0].Vulns) != 0 {
		pkgPath = ghsas[0].Vulns[0].Package
	}
	// Put all the identifiers in the title.
	var (
		ids    []string
		bodies []string
	)
	repo, err := gitrepo.Clone(ctx, "https://github.com/golang/vulndb")
	if err != nil {
		return err
	}
	_, allReports, err := report.All(repo)
	if err != nil {
		return err
	}
	for _, sa := range ghsas {
		for _, id := range sa.Identifiers {
			ids = append(ids, id.Value)
		}
		body, err := worker.CreateGHSABody(sa, allReports, pc)
		if err != nil {
			return err
		}
		bodies = append(bodies, body)
	}
	sort.Strings(ids)
	iss := &issues.Issue{
		Title:  fmt.Sprintf("x/vulndb: potential Go vuln in %s: %s", pkgPath, strings.Join(ids, ", ")),
		Body:   strings.Join(bodies, "\n\n----------\n\n"),
		Labels: labels,
	}
	issNum, err := c.CreateIssue(ctx, iss)
	if err != nil {
		return err
	}
	fmt.Printf("created https://github.com/golang/vulndb/issues/%d (%s)\n", issNum, strings.Join(ids, ", "))
	return nil
}

type record struct {
	identifier string
	category   string
}

func parseAliases(filename string) (aliases []string, err error) {
	lines, err := internal.ReadFileLines(filename)
	if err != nil {
		return nil, err
	}
	aliases = append(aliases, lines...)
	return aliases, nil
}

func parseExcluded(filename string) (records []*record, err error) {
	lines, err := internal.ReadFileLines(filename)
	if err != nil {
		return nil, err
	}
	for i, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			return nil, fmt.Errorf("wrong number of fields on line %d: %q", i, line)
		}
		r := &record{
			category:   parts[0],
			identifier: parts[1],
		}
		records = append(records, r)
	}
	return records, nil
}
