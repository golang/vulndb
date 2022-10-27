// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command cve provides utilities for managing CVE IDs and CVE Records via the
// MITRE CVE Services API.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/vulndb/internal/cveclient"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/report"
)

var (
	apiKey = flag.String("key",
		os.Getenv("CVE_API_KEY"), "key for accessing the CVE API (can also be set via env var CVE_API_KEY)")
	apiUser = flag.String("user",
		os.Getenv("CVE_API_USER"), "username for accessing the CVE API (can also be set via env var CVE_API_USER)")
	testApiKey = flag.String("test-key",
		os.Getenv("TEST_CVE_API_KEY"), "key for accessing the CVE API in test env (can also be set via env var TEST_CVE_API_KEY)")
	testApiUser = flag.String("test-user",
		os.Getenv("TEST_CVE_API_USER"), "username for accessing the CVE API in test env (can also be set via env var TEST_CVE_API_USER)")
	apiOrg = flag.String("org",
		"Go", "organization name for accessing the CVE API")
	// Note: the cve tool does not currently support the dev endpoint as there
	// is no clear use case for us.
	test = flag.Bool("test", false, "whether to access the CVE API in the test environment")

	// flags for the reserve command
	reserveN          = flag.Int("n", 1, "reserve: the number of new CVE IDs to reserve")
	reserveSequential = flag.Bool("seq", true, "reserve: if true, reserve new CVE ID batches in sequence")

	// flags for the list command
	listState = flag.String("state", "", "list: filter by CVE state (RESERVED, PUBLIC, or REJECT)")

	// flags for the publish command
	publishUpdate = flag.Bool("update", false, "publish: if true, update an existing CVE Record")

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
		fmt.Fprintf(out, formatCmd, "record {cve-id}", "outputs the record associated with a CVE ID (CVE-YYYY-NNNN)")
		fmt.Fprintf(out, formatCmd, "[-update] publish {filename}", "publishes a CVE Record from a YAML or JSON file")
		fmt.Fprintf(out, formatCmd, "org", "outputs details on the authenticated organization")
		fmt.Fprintf(out, formatCmd, "[-year] [-state] list", "lists all CVE IDs for an organization")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		logFatalUsageErr("cve", fmt.Errorf("must provide subcommand"))
	}

	c := cveclient.New(*getCfgFromFlags())

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
			logFatalUsageErr("cve id", err)
		}
		if err := lookupID(c, id); err != nil {
			log.Fatalf("cve id: could not retrieve CVE IDs due to error:\n  %v", err)
		}
	case "record":
		id, err := validateID(flag.Arg(1))
		if err != nil {
			logFatalUsageErr("cve record", err)
		}
		// TODO(https://go.dev/issue/53256): Remove when record lookup is
		// supported by CVE Services API.
		if !*test {
			logUnsupportedErr("cve record")
		}
		if err := lookupRecord(c, id); err != nil {
			log.Fatalf("cve record: could not retrieve CVE record due to error:\n  %v", err)
		}
	case "publish":
		filename := flag.Arg(1)
		if filename == "" {
			logFatalUsageErr("cve publish", errors.New("filename must be provided"))
		}
		if !strings.HasSuffix(filename, ".json") && !strings.HasSuffix(filename, ".yaml") {
			logFatalUsageErr("cve publish", errors.New("filename must end in '.json' or '.yaml'"))
		}
		// TODO(https://go.dev/issue/53256): Remove when record publish is
		// supported by CVE Services API.
		if !*test {
			logUnsupportedErr("cve publish")
		}
		if err := publish(c, filename, *publishUpdate); err != nil {
			log.Fatalf("cve publish: could not publish CVE record due to error:\n %v", err)
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
				logFatalUsageErr("cve list", err)
			}
			filters.State = state
			filters.Year = *year
		}
		if err := list(c, filters); err != nil {
			log.Fatalf("cve list: could not retrieve CVE IDs due to error:\n  %v", err)
		}
	default:
		logFatalUsageErr("cve", fmt.Errorf("unsupported command: %q", cmd))
	}
}

func logFatalUsageErr(context string, err error) {
	log.Printf("%s: %s\n\n", context, err)
	flag.Usage()
	os.Exit(1)
}

func logUnsupportedErr(context string) {
	log.Fatalf("%s: command not yet supported by MITRE CVE Services API", context)
}

func getCurrentYear() int {
	year, _, _ := time.Now().Date()
	return year
}

func getCfgFromFlags() *cveclient.Config {
	if *test {
		if *testApiKey == "" {
			logFatalUsageErr("cve", errors.New("the test CVE API key (flag -test-key or env var TEST_CVE_API_KEY) must be set in test env"))
		}
		if *testApiUser == "" {
			logFatalUsageErr("cve", errors.New("the test CVE API user (flag -test-user or env var TEST_CVE_API_USER) must be set in test env"))
		}
		return &cveclient.Config{
			Endpoint: cveclient.TestEndpoint,
			Key:      *testApiKey,
			Org:      *apiOrg,
			User:     *testApiUser,
		}
	}

	if *apiKey == "" {
		logFatalUsageErr("cve", errors.New("the CVE API key (flag -key or env var CVE_API_KEY) must be set in prod env"))
	}
	if *apiUser == "" {
		logFatalUsageErr("cve", errors.New("the CVE API user (flag -user or env var CVE_API_USER) must be set in prod env"))
	}
	return &cveclient.Config{
		Endpoint: cveclient.ProdEndpoint,
		Key:      *apiKey,
		Org:      *apiOrg,
		User:     *apiUser,
	}
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
	fmt.Println(cves.ShortString())
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
	assigned, err := c.RetrieveID(id)
	if err != nil {
		return err
	}
	// Display the retrieved CVE ID metadata.
	fmt.Println(assigned)
	return nil
}

func recordToString(r *cveschema5.CVERecord) string {
	s, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		s = []byte(fmt.Sprint(r))
	}
	return string(s)
}

func lookupRecord(c *cveclient.Client, id string) error {
	record, err := c.RetrieveRecord(id)
	if err != nil {
		return err
	}
	// Display the retrieved CVE record.
	fmt.Println(recordToString(record))
	return nil
}

func publish(c *cveclient.Client, filename string, update bool) (err error) {
	var toPublish *cveschema5.CVERecord
	switch {
	case strings.HasSuffix(filename, ".yaml"):
		toPublish, err = report.ToCVE5(filename)
		if err != nil {
			return err
		}
	case strings.HasSuffix(filename, ".json"):
		toPublish, err = cveschema5.Read(filename)
		if err != nil {
			return err
		}
	default:
		return errors.New("filename must end in '.json' or '.yaml'")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("ready to publish:\n%s\ncontinue? (y/N)\n", recordToString(toPublish))
	text, _ := reader.ReadString('\n')
	if text != "y\n" {
		fmt.Println("exiting")
		return nil
	}

	var (
		published *cveschema5.CVERecord
		action    string
	)
	if update {
		published, err = c.UpdateRecord(toPublish.Metadata.ID, &toPublish.Containers)
		if err != nil {
			return err
		}
		action = "update"
	} else {
		published, err = c.CreateRecord(toPublish.Metadata.ID, &toPublish.Containers)
		if err != nil {
			return err
		}
		action = "create"
	}
	fmt.Printf("successfully %sd record for %s:\n%v\nlink: %s%s\n", action, published.Metadata.ID, recordToString(published), report.NISTPrefix, published.Metadata.ID)
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
