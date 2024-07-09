// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command triage provides direct access to the triage algorithm
// in internal/triage (used by the worker), which determines whether
// an external vuln likely affects Go or not.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"text/tabwriter"

	"golang.org/x/vulndb/internal/cveutils"
	"golang.org/x/vulndb/internal/idstr"
)

func init() {
	out := flag.CommandLine.Output()
	flag.Usage = func() {
		fmt.Fprintf(out, "usage:\n")
		tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
		fmt.Fprintf(tw, "  triage\t%s\t%s\n", "[<GHSA> | <CVE>]", "triage the given IDs")
		fmt.Fprintf(tw, "  triage\t%s\t%s\n", "latest-cves", "triage all the CVEs added/updated in the last month (VERY SLOW)")
		tw.Flush()
	}
}

func main() {
	flag.Parse()

	args := flag.Args()[0:]

	if len(args) < 1 {
		flag.Usage()
		log.Fatal("argument(s) required")
	}

	ctx := context.Background()

	if len(args) == 1 {
		switch args[0] {
		case "latest-cves":
			cves, err := cveutils.Latest()
			if err != nil {
				log.Fatal(err)
			}
			triageCVEs(ctx, cves)
			return
		}
	}

	var ghsas, cves []string
	for _, arg := range args {
		switch {
		case idstr.IsCVE(arg):
			cves = append(cves, arg)
		case idstr.IsGHSA(arg):
			ghsas = append(ghsas, arg)
		default:
			flag.Usage()
			log.Fatalf("unrecognized arg %s", arg)
		}
	}

	triageCVEs(ctx, cves)
	triageGHSAs(ctx, ghsas)
}
