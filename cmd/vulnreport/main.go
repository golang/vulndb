// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command vulnreport provides a tool for creating a YAML vulnerability report for
// x/vulndb.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"os"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker"
	"gopkg.in/yaml.v2"
)

var (
	localRepoPath = flag.String("local-cve-repo", "", "path to local repo, instead of cloning remote")
	issueRepo     = flag.String("issue-repo", "github.com/golang/vulndb", "repo to create issues in")
	githubToken   = flag.String("ghtoken", os.Getenv("VULN_GITHUB_ACCESS_TOKEN"), "GitHub access token")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: vulnreport [cmd] [filename.yaml]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  create [githubIssueNumber]: creates a new vulnerability YAML report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  lint [filename.yaml]: lints a vulnerability YAML report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  newcve [filename.yaml]: creates a CVE report from the provided YAML report\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	name := flag.Arg(1)
	switch cmd {
	case "create":
		if *githubToken == "" {
			flag.Usage()
			log.Fatalf("githubToken must be provided")
		}
		githubID, err := strconv.Atoi(name)
		if err != nil {
			log.Fatal(err)
		}
		if err := create(context.Background(), githubID, *githubToken, *issueRepo, *localRepoPath); err != nil {
			log.Fatal(err)
		}
	case "lint":
		if err := lint(name); err != nil {
			log.Fatal(err)
		}
	case "newcve":
		if err := newCVE(name); err != nil {
			log.Fatal(err)
		}
	default:
		flag.Usage()
		log.Fatalf("unsupported command: %q", cmd)
	}
}

func create(ctx context.Context, issueNumber int, ghToken, issueRepo, repoPath string) (err error) {
	defer derrors.Wrap(&err, "create(%d)", issueNumber)
	owner, repoName, err := worker.ParseGithubRepo(issueRepo)
	if err != nil {
		return err
	}
	c := worker.NewGithubIssueClient(owner, repoName, ghToken)
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
	cve, err := worker.FetchCVE(ctx, repoPath, cveID)
	if err != nil {
		return err
	}
	r := report.CVEToReport(cve, modulePath)
	out, err := yaml.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(fmt.Sprintf("reports/GO-2021-%04d.yaml", issueNumber), out, 0644)
}

func lint(filename string) (err error) {
	defer derrors.Wrap(&err, "lint(%q)", filename)
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile: %v", err)
	}

	var vuln report.Report
	err = yaml.UnmarshalStrict(content, &vuln)
	if err != nil {
		return fmt.Errorf("yaml.UnmarshalStrict: %v", err)
	}

	if lints := vuln.Lint(); len(lints) > 0 {
		return fmt.Errorf("vuln.Lint returned errors:\n\t %s", strings.Join(lints, "\n\t"))
	}
	return nil
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
