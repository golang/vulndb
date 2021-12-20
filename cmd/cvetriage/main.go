// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command cvetriage is used to manage the processing and triaging of CVE data
// from the github.com/CVEProject/cvelist git repository. It is intended to be
// run by a third-party scheduler, such as Cloud Run, at some predefined interval.
//
// Running this tool will do the following: run the tool does the following things:
//  1. Reads each CVE JSON file, filtering them based on possible indicators
//     that the CVE is related to a Go project.
//  2. Reads a list of already processed CVEs (currently stored at
//     triaged-cve-list, but will likely be moved to a database in the future), skipping
//     any CVEs from the previous step that have already been processed.
//  3. For each unprocessed CVE, a preliminary YAML vulnerability report will be generated, and a
//     GitHub issue will be created.
package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"golang.org/x/vulndb/internal"
	"golang.org/x/vulndb/internal/derrors"
)

func main() {
	flag.Parse()
	args := flag.Args()

	var repoPath string
	switch len(args) {
	case 0:
	case 1:
		repoPath = args[0]
	default:
		log.Fatalf("unexpected number of args: %v", args)
	}
	if err := run(repoPath); err != nil {
		log.Fatal(err)
	}
}

func run(repoPath string) (err error) {
	triaged, err := readTriagedCVEList()
	if err != nil {
		return err
	}
	return Run(repoPath, triaged)
}

const (
	triagedCVEList      = "triaged-cve-list"
	statusFalsePositive = "false-positive"
	statusTriaged       = "triaged"
)

func readTriagedCVEList() (_ map[string]string, err error) {
	defer derrors.Wrap(&err, "readTriagedCVEList()")
	triaged := map[string]string{}
	lines, err := internal.ReadFileLines(triagedCVEList)
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		vuln := strings.Fields(l)
		if len(vuln) < 2 {
			return nil, fmt.Errorf("unexpected syntax: %q", l)
		}
		var (
			cveID = vuln[0]
			state = vuln[1]
		)
		if state != statusFalsePositive && state != statusTriaged {
			return nil, fmt.Errorf("unexpected syntax: %q", l)
		}
		if state == statusTriaged {
			if len(vuln) != 3 {
				return nil, fmt.Errorf("unexpected syntax: %q", l)
			}
			triaged[cveID] = state
		}
		if state == statusFalsePositive {
			triaged[cveID] = state
		}
	}
	return triaged, nil
}
