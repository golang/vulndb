// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command vulnreport provides a tool for creating a YAML vulnerability report for
// x/vulndb.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"

	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

var (
	githubToken = flag.String("ghtoken", "", "GitHub access token (default: value of VULN_GITHUB_ACCESS_TOKEN)")
	cpuprofile  = flag.String("cpuprofile", "", "write cpuprofile to this file")
	quiet       = flag.Bool("q", false, "quiet mode (suppress info logs)")
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
		fmt.Fprintf(flag.CommandLine.Output(), "  symbols filename.yaml: finds and populates possible vulnerable symbols for a given report\n")
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
	case "symbols":
		cmdFunc = func(ctx context.Context, name string) error { return findSymbols(ctx, name) }
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
