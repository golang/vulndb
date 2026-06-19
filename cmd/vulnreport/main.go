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
	"log"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"text/tabwriter"

	vlog "golang.org/x/vulndb/cmd/vulnreport/log"
)

var (
	githubToken   = flag.String("ghtoken", "", "GitHub access token (default: value of VULN_GITHUB_ACCESS_TOKEN)")
	cpuprofile    = flag.String("cpuprofile", "", "write cpuprofile to this file")
	quiet         = flag.Bool("q", false, "quiet mode (suppress info logs)")
	colorize      = flag.Bool("color", os.Getenv("NO_COLOR") == "", "show colors in logs")
	issueRepo     = flag.String("issue-repo", "github.com/golang/vulndb", "repo to locate GitHub issues")
	reportRepo    = flag.String("local-repo", ".", "local path to repo to locate YAML reports")
	skippedIssues []int
)

func init() {
	flag.Func("skip-issues", "for triage, create, create-excluded, and commit, whitespace-delimited list of GitHub issues to skip", func(s string) error {
		is, err := parseSkipIssues(s)
		if err != nil {
			return err
		}
		skippedIssues = append(skippedIssues, is...)
		return nil
	})

	out := flag.CommandLine.Output()
	flag.Usage = func() {
		if _, err := fmt.Fprintf(out, "usage: vulnreport [flags] [cmd] [args]\n\n"); err != nil {
			panic(err)
		}
		tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
		for _, command := range commands {
			argUsage, desc := command.usage()
			if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\n", command.name(), argUsage, desc); err != nil {
				panic(err)
			}
		}
		if err := tw.Flush(); err != nil {
			panic(err)
		}
		if _, err := fmt.Fprint(out, "\nsupported flags:\n\n"); err != nil {
			panic(err)
		}
		flag.PrintDefaults()
	}
}

// The subcommands supported by vulnreport.
// To add a new command, implement the command interface and
// add the command to this list.
var commands = map[string]command{
	"create":          &create{},
	"create-excluded": &createExcluded{},
	"commit":          &commit{},
	"cve":             &cveCmd{},
	"triage":          &triage{},
	"fix":             &fix{},
	"lint":            &lint{},
	"regen":           &regenerate{},
	"review":          &review{},
	"set-dates":       &setDates{},
	"suggest":         &suggest{},
	"symbols":         &symbolsCmd{},
	"osv":             &osvCmd{},
	"unexclude":       &unexclude{},
	"withdraw":        &withdraw{},
	"xref":            &xref{},
}

func main() {
	ctx := context.Background()

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		log.Fatal("subcommand required")
	}

	if *quiet {
		vlog.SetQuiet()
	}
	if !*colorize {
		vlog.RemoveColor()
	}

	if *githubToken == "" {
		*githubToken = os.Getenv("VULN_GITHUB_ACCESS_TOKEN")
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

	cmdName := flag.Arg(0)
	args := flag.Args()[1:]

	cmd, ok := commands[cmdName]
	if !ok {
		flag.Usage()
		log.Fatalf("unsupported command: %q", cmdName)
	}

	if err := run(ctx, cmd, args, defaultEnv()); err != nil {
		log.Fatalf("%s: %s", cmdName, err)
	}
}

func parseSkipIssues(s string) ([]int, error) {
	skipped := []int{}
	for part := range strings.FieldsSeq(s) {
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		skipped = append(skipped, num)
	}
	return skipped, nil
}
