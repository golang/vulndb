// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command cve provides utilities for managing CVE IDs and CVE Records via the
// MITRE CVE Services API.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"golang.org/x/vulndb/internal/cveclient"
)

var (
	apiKey = flag.String("key",
		os.Getenv("CVE_API_KEY"), "key for accessing the CVE API (can also be set via env var CVE_API_KEY)")
	apiUser = flag.String("user",
		os.Getenv("CVE_API_USER"), "username for accessing the CVE API (can also be set via env var CVE_API_USER)")
	apiOrg = flag.String("org",
		"Go", "organization name for accessing the CVE API")
	test = flag.Bool("test", false, "whether to access the CVE API in the test environment")

	// flags for the reserve command
	reserveN          = flag.Int("n", 1, "reserve: the number of new CVE IDs to reserve")
	reserveSequential = flag.Bool("seq", true, "reserve: if true, reserve new CVE ID batches in sequence")

	// flags for the list command
	listState = flag.String("state", "", "list: filter by CVE state (RESERVED, PUBLIC, or REJECT)")

	// flags that apply to multiple commands
	year = flag.Int("year", 0, "reserve: the CVE ID year for newly reserved CVE IDs (default is current year)\nlist: filter by the year in the CVE ID")
)

func main() {
	out := flag.CommandLine.Output()
	flag.Usage = func() {
		fmt.Fprintln(out, "Command cve provides utilities for managing CVE IDs and CVE Records via the MITRE CVE Services API")
		formatCmd := "    %s: %s\n"
		fmt.Fprintf(out, "usage: cve [-key] [-user] [-org] [-test] <cmd> ...\n  commands:\n")
		fmt.Fprintf(out, formatCmd, "[-n] [-seq] [-year] reserve", "reserves new CVE IDs")
		fmt.Fprintf(out, formatCmd, "quota", "outputs the CVE ID quota of the authenticated organization")
		fmt.Fprintf(out, formatCmd, "id {cve-id}", "outputs details on an assigned CVE ID (CVE-YYYY-NNNN)")
		fmt.Fprintf(out, formatCmd, "org", "outputs details on the authenticated organization")
		fmt.Fprintf(out, formatCmd, "[-year] [-state] list", "lists all CVE IDs for an organization")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		logUsageErr("cve", fmt.Errorf("must provide subcommand"))
	}

	// The cve tool does not currently support the dev endpoint as there is
	// no clear use case for us.
	endpoint := cveclient.ProdEndpoint
	if *test {
		endpoint = cveclient.TestEndpoint
	}

	if *apiKey == "" {
		logUsageErr("cve", errors.New("the CVE API key (flag -key or env var CVE_API_KEY) must be set"))
	}
	if *apiUser == "" {
		logUsageErr("cve", errors.New("the CVE API user (flag -user or env var CVE_API_USER) must be set"))
	}

	cfg := cveclient.Config{
		Endpoint: endpoint,
		Key:      *apiKey,
		Org:      *apiOrg,
		User:     *apiUser,
	}
	c := cveclient.New(cfg)

	cmd := flag.Arg(0)
	switch cmd {
	case "help":
		flag.Usage()
	case "reserve":
		year := *year
		if year == 0 {
			year = getCurrentYear()
		}
		mode := cveclient.SequentialRequest
		if !*reserveSequential {
			mode = cveclient.NonsequentialRequest
		}
		if err := reserve(c, cveclient.ReserveOptions{
			NumIDs: *reserveN,
			Year:   year,
			Mode:   mode,
		}); err != nil {
			log.Fatalf("cve reserve: could not reserve any new CVEs due to error:\n  %v", err)
		}
	case "quota":
		if err := quota(c); err != nil {
			log.Fatalf("cve quota: could not retrieve quota info due to error:\n  %v", err)
		}
	case "id":
		id, err := validateID(flag.Arg(1))
		if err != nil {
			logUsageErr("cve id", err)
		}
		if err := lookupID(c, id); err != nil {
			log.Fatalf("cve id: could not retrieve CVE IDs due to error:\n  %v", err)
		}
	case "org":
		if err := lookupOrg(c); err != nil {
			log.Fatalf("cve org: could not retrieve org info due to error:\n  %v", err)
		}
	case "list":
		// TODO(http://go.dev/issues/53258): allow time-based filters via flags.
		var filters *cveclient.ListOptions
		if *listState != "" || *year != 0 {
			filters = new(cveclient.ListOptions)
			state, err := validateState(*listState)
			if err != nil {
				logUsageErr("cve list", err)
			}
			filters.State = state
			filters.Year = *year
		}
		if err := list(c, filters); err != nil {
			log.Fatalf("cve list: could not retrieve CVE IDs due to error:\n  %v", err)
		}
	default:
		logUsageErr("cve", fmt.Errorf("unsupported command: %q", cmd))
	}
}

func logUsageErr(context string, err error) {
	log.Printf("%s: %s\n\n", context, err)
	flag.Usage()
	os.Exit(1)
}

func getCurrentYear() int {
	year, _, _ := time.Now().Date()
	return year
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func validateID(id string) (string, error) {
	if id == "" {
		return "", errors.New("CVE ID must be provided")
	}
	if !cveRegex.MatchString(id) {
		return "", fmt.Errorf("%q is not a valid CVE ID", id)
	}
	return id, nil
}

var stateRegex = regexp.MustCompile(`^(RESERVED|PUBLIC|REJECT)$`)

func validateState(state string) (string, error) {
	if state != "" && !stateRegex.MatchString(state) {
		return "", fmt.Errorf("state must match regex %v", stateRegex)
	}
	return state, nil
}

func reserve(c *cveclient.Client, opts cveclient.ReserveOptions) error {
	cves, err := c.ReserveIDs(opts)
	if err != nil {
		return err
	}
	cvesReserved := len(cves)
	if cvesReserved < opts.NumIDs {
		fmt.Printf("warning: only %d of %d requested CVE IDs were reserved\n",
			len(cves), opts.NumIDs)
	}
	fmt.Printf("successfully reserved %d CVE IDs:\n  %v\n", cvesReserved, cves.ShortString())
	return nil
}

func quota(c *cveclient.Client) error {
	quota, err := c.RetrieveQuota()
	if err != nil {
		return err
	}
	fmt.Printf("quota info for org %q:\n  quota: %d\n  total reserved: %d\n  available:  %d\n", c.Org, quota.Quota, quota.Reserved, quota.Available)
	return nil
}

func lookupOrg(c *cveclient.Client) error {
	org, err := c.RetrieveOrg()
	if err != nil {
		return err
	}
	fmt.Printf("org name: %q\nshort name: %q\nuuid: %s\n", org.Name, org.ShortName, org.UUID)
	return nil
}

func lookupID(c *cveclient.Client, id string) error {
	cve, err := c.RetrieveID(id)
	if err != nil {
		return err
	}
	fmt.Println(cve)
	return nil
}

func list(c *cveclient.Client, lf *cveclient.ListOptions) error {
	cves, err := c.ListOrgCVEs(lf)
	if err != nil {
		return err
	}
	var filterString string
	if lf != nil {
		filterString = fmt.Sprintf(" with filters %s", lf)
	}
	if n := len(cves); n > 0 {
		fmt.Printf("found %d CVE IDs for org %q%s:\n%v\n", n, c.Org, filterString, cves)
	} else {
		fmt.Printf("found no CVE IDs for org %q%s\n", c.Org, filterString)
	}
	return nil
}
