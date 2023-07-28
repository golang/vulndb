// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command inspect provides insights into the current contents of vulndb.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/vulndb/internal/ghsarepo"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/report"
)

var (
	localGHSA = flag.String("local-ghsa", "", "path to local GHSA repo, instead of cloning remote")
	detail    = flag.Bool("detail", false, "if true, print more details on GHSAs not yet in vulndb")
)

func main() {
	start := time.Now()
	flag.Parse()
	localRepo, err := gitrepo.Open(context.Background(), ".")
	if err != nil {
		log.Fatal(err)
	}
	byIssue, _, err := report.All(localRepo)
	if err != nil {
		log.Fatal(err)
	}
	reports := maps.Values(byIssue)

	var c *ghsarepo.Client
	if *localGHSA != "" {
		repo, err := gitrepo.Open(context.Background(), *localGHSA)
		if err != nil {
			log.Fatal(err)
		}
		c, err = ghsarepo.NewClientFromRepo(repo)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Println("cloning remote GHSA repo (use -local-ghsa to speed this up)...")
		c, err = ghsarepo.NewClient()
		if err != nil {
			log.Fatal(err)
		}
	}

	ghsas := c.IDs()
	summary := summarize(ghsas, reports)

	fmt.Printf("=== Summary (%s) ===\n", time.Since(start).Truncate(time.Millisecond))
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 1, ' ', 0)
	fmt.Fprintf(tw, "%s\t%4d\n", "Go reports", len(reports))
	fmt.Fprintf(tw, "-- %s\t%4d\n", "Regular Go reports", summary.regular)
	fmt.Fprintf(tw, "-- %s\t%4d\n", "Excluded Go reports", summary.excluded)
	fmt.Fprintf(tw, "-- %s\t%4d\n", "Go reports with no GHSA (+)", len(summary.noGHSA))
	fmt.Fprintf(tw, "%s\t%4d\n", "GHSAs affecting Go", len(ghsas))
	fmt.Fprintf(tw, "-- %s\t%4d\n", "GHSAs not yet in vulndb (++)", len(summary.ghsasNotInVDB))
	tw.Flush()
	fmt.Println()
	fmt.Println("(+) \"Go reports with no GHSA\" are published third-party Go reports with no corresponding GHSA. (This isn't a problem; it's informational only.)")
	fmt.Println("(++) \"GHSAs not yet in vulndb\" are published GHSAs with no corresponding Go report. There may already be an open issue on the tracker for these.")

	if *detail {
		fmt.Println("\n=== GHSAs not yet in vulndb ===")
		for i, g := range summary.ghsasNotInVDB {
			fmt.Println()
			fmt.Printf("%d) %s\n", i+1, g)
			fmt.Printf("https://github.com/advisories/%s\n", g)
			fmt.Printf("search issue tracker: https://github.com/golang/vulndb/issues?q=is%%3Aissue+%s\n", g)
		}
	}
}

type summary struct {
	regular, excluded int
	ghsasNotInVDB     []string
	noGHSA            []string
}

func summarize(ghsas []string, reports []*report.Report) *summary {
	ghsasWithReport := make(map[string]bool)
	var noGHSA []string
	var regular, excluded int

	for _, r := range reports {
		if r.IsExcluded() {
			excluded++
		} else {
			regular++
		}
		if len(r.GHSAs) == 0 && r.CVEMetadata == nil {
			noGHSA = append(noGHSA, r.ID)
		}
		for _, ghsa := range r.GHSAs {
			ghsasWithReport[ghsa] = true
		}
	}

	var ghsasNotInVDB []string
	for _, ghsa := range ghsas {
		if _, ok := ghsasWithReport[ghsa]; !ok {
			ghsasNotInVDB = append(ghsasNotInVDB, ghsa)
		}
	}

	return &summary{
		regular:       regular,
		excluded:      excluded,
		ghsasNotInVDB: ghsasNotInVDB,
		noGHSA:        noGHSA,
	}
}
