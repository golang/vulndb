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
	"text/tabwriter"

	vlog "golang.org/x/vulndb/cmd/vulnreport/log"
)

var (
	githubToken = flag.String("ghtoken", "", "GitHub access token (default: value of VULN_GITHUB_ACCESS_TOKEN)")
	cpuprofile  = flag.String("cpuprofile", "", "write cpuprofile to this file")
	quiet       = flag.Bool("q", false, "quiet mode (suppress info logs)")
	colorize    = flag.Bool("color", os.Getenv("NO_COLOR") == "", "show colors in logs")
)

func init() {
	out := flag.CommandLine.Output()
	flag.Usage = func() {
		fmt.Fprintf(out, "usage: vulnreport [flags] [cmd] [args]\n\n")
		tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
		for _, command := range commands {
			argUsage, desc := command.usage()
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", command.name(), argUsage, desc)
		}
		tw.Flush()
		fmt.Fprint(out, "\nsupported flags:\n\n")
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
	"duplicates":      &duplicates{},
	"fix":             &fix{},
	"lint":            &lint{},
	"set-dates":       &setDates{},
	"suggest":         &suggest{},
	"symbols":         &symbolsCmd{},
	"osv":             &osvCmd{},
	"unexclude":       &unexclude{},
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

	if err := run(ctx, cmd, args); err != nil {
		log.Fatalf("%s: %s", cmdName, err)
	}
}
