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
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/idstr"
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
	listState = flag.String("state", "", "list: filter by CVE state (RESERVED, PUBLISHED, or REJECTED)")

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
		fmt.Fprintf(out, formatCmd, "reject {cve-id}", "rejects the CVE ID (CVE-YYYY-NNNN) - for CVEs that have been reserved but are no longer needed")
		fmt.Fprintf(out, formatCmd, "publish [{filename} | {issue ID}]", "publishes or updates a CVE Record from a YAML/JSON file or issue ID")
		fmt.Fprintf(out, formatCmd, "org", "outputs details on the authenticated organization")
		fmt.Fprintf(out, formatCmd, "[-year] [-state] list", "lists all CVE IDs for an organization")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() < 1 {
		logFatalUsageErr("cve", fmt.Errorf("must provide subcommand"))
	}

	c := cve5.NewClient(*cfgFromFlags())

	cmd := flag.Arg(0)
	switch cmd {
	case "help":
		flag.Usage()
	case "reserve":
		year := *year
		if year == 0 {
			year = currentYear()
		}
		mode := cve5.SequentialRequest
		if !*reserveSequential {
			mode = cve5.NonsequentialRequest
		}
		if err := reserve(c, cve5.ReserveOptions{
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
		if err := lookupRecord(c, id); err != nil {
			log.Fatalf("cve record: could not retrieve CVE record due to error:\n  %v", err)
		}
	case "reject":
		args := flag.Args()[1:]
		if len(args) == 0 {
			logFatalUsageErr("cve reject", errors.New("must provide CVE ID"))
		}
		for _, arg := range args {
			if !idstr.IsCVE(arg) {
				log.Printf("%s is not a CVE id; skipping", arg)
				continue
			}
			if err := c.Reject(arg, "reserved but not needed"); err != nil {
				log.Printf("cve reject: could not reject CVE due to error:\n %v", err)
			} else {
				log.Printf("success: rejected CVE %s", arg)
			}
		}
	case "publish":
		args := flag.Args()[1:]
		if len(args) == 0 {
			logFatalUsageErr("cve publish", errors.New("must provide filename or issue ID"))
		}
		for _, arg := range args {
			filename, err := argToFilename(arg)
			if err != nil {
				logFatalUsageErr("cve publish", err)
			}
			if !strings.HasSuffix(filename, ".json") && !strings.HasSuffix(filename, ".yaml") {
				logFatalUsageErr("cve publish", errors.New("filename must end in '.json' or '.yaml'"))
			}
			if err := publish(c, filename); err != nil {
				log.Printf("cve publish: could not publish CVE record due to error:\n %v", err)
			}
		}
	case "org":
		if err := lookupOrg(c); err != nil {
			log.Fatalf("cve org: could not retrieve org info due to error:\n  %v", err)
		}
	case "list":
		// TODO(http://go.dev/issues/53258): allow time-based filters via flags.
		var filters *cve5.ListOptions
		if *listState != "" || *year != 0 {
			filters = new(cve5.ListOptions)
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
	flag.Usage()
	log.Fatalf("%s: %s\n", context, err)
}

func currentYear() int {
	year, _, _ := time.Now().Date()
	return year
}

func cfgFromFlags() *cve5.Config {
	if *test {
		if *testApiKey == "" {
			logFatalUsageErr("cve", errors.New("the test CVE API key (flag -test-key or env var TEST_CVE_API_KEY) must be set in test env"))
		}
		if *testApiUser == "" {
			logFatalUsageErr("cve", errors.New("the test CVE API user (flag -test-user or env var TEST_CVE_API_USER) must be set in test env"))
		}
		return &cve5.Config{
			Endpoint: cve5.TestEndpoint,
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
	return &cve5.Config{
		Endpoint: cve5.ProdEndpoint,
		Key:      *apiKey,
		Org:      *apiOrg,
		User:     *apiUser,
	}
}

func validateID(id string) (string, error) {
	if id == "" {
		return "", errors.New("CVE ID must be provided")
	}
	if !idstr.IsCVE(id) {
		return "", fmt.Errorf("%q is not a valid CVE ID", id)
	}
	return id, nil
}

var stateRegex = regexp.MustCompile(`^(RESERVED|PUBLISHED|REJECTED)$`)

func validateState(state string) (cve5.State, error) {
	if state != "" && !stateRegex.MatchString(state) {
		return "", fmt.Errorf("state must match regex %v", stateRegex)
	}
	return cve5.State(state), nil
}

func reserve(c *cve5.Client, opts cve5.ReserveOptions) error {
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

func quota(c *cve5.Client) error {
	quota, err := c.RetrieveQuota()
	if err != nil {
		return err
	}
	fmt.Printf("quota info for org %q:\n  quota: %d\n  total reserved: %d\n  available:  %d\n", c.Org, quota.Quota, quota.Reserved, quota.Available)
	return nil
}

func lookupOrg(c *cve5.Client) error {
	org, err := c.RetrieveOrg()
	if err != nil {
		return err
	}
	fmt.Printf("org name: %q\nshort name: %q\nuuid: %s\n", org.Name, org.ShortName, org.UUID)
	return nil
}

func lookupID(c *cve5.Client, id string) error {
	assigned, err := c.RetrieveID(id)
	if err != nil {
		return err
	}
	// Display the retrieved CVE ID metadata.
	fmt.Println(assigned)
	return nil
}

// toJSON converts a struct into a JSON string.
// If JSON marshal fails, it falls back to fmt.Sprint.
func toJSON(v any) string {
	s, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(s)
}

func lookupRecord(c *cve5.Client, id string) error {
	record, err := c.RetrieveRecord(id)
	if err != nil {
		return err
	}
	// Display the retrieved CVE record.
	fmt.Println(toJSON(record))
	return nil
}

func argToFilename(arg string) (string, error) {
	if arg == "" {
		return "", errors.New("filename or issue ID must be provided")
	}
	if _, err := os.Stat(arg); err != nil {
		// If arg isn't a file, see if it might be an issue ID
		// with an existing CVE record.
		for _, padding := range []string{"", "0", "00", "000"} {
			m, _ := filepath.Glob("data/cve/v5/GO-*-" + padding + arg + ".json")
			if len(m) == 1 {
				return m[0], nil
			}
		}
		return "", fmt.Errorf("could not parse argument %q: not a valid filename or issue ID with existing record", arg)
	}
	return arg, nil
}

func publish(c *cve5.Client, filename string) (err error) {
	if !strings.HasSuffix(filename, ".json") {
		return errors.New("filename must end in '.json'")
	}

	cveID, toPublish, err := cve5.ReadForPublish(filename)
	if err != nil {
		return err
	}

	// Determine if the record should be created or updated.
	assigned, err := c.RetrieveID(cveID)
	if err != nil {
		return err
	}

	var (
		publishFunc func(string, *cve5.Containers) (*cve5.CVERecord, error)
		action      string
	)
	switch state := assigned.State; state {
	case cve5.StatePublished:
		existing, err := c.RetrieveRecord(cveID)
		if err != nil {
			return err
		}
		fmt.Printf("%s is published at %s\n", cveID, c.WebURL(cveID))
		if diff := cmp.Diff(existing.Containers, *toPublish); diff != "" {
			fmt.Printf("publish would update record with diff (-existing, +new):\n%s\n", diff)
			// The CVE program sometimes adds references to CVEs, so we need
			// to make sure we don't accidentally delete them.
			if updated := handleDeleted(existing, toPublish, filename); updated {
				// If we updated the CVE, check if any changes remain.
				_, toPublish, err = cve5.ReadForPublish(filename)
				if err != nil {
					return err
				}
				if diff := cmp.Diff(existing.Containers, *toPublish); diff == "" {
					fmt.Println("after adding missing refs, updating record would now have no effect")
					return nil
				}
				fmt.Printf("after adding missing refs, publish would now update record with diff (-existing, +new):\n%s\n", diff)
			}
		} else {
			fmt.Println("updating record would have no effect, skipping")
			return nil
		}
		publishFunc = c.UpdateRecord
		action = "update"
	case cve5.StateReserved:
		fmt.Printf("publish would create new record for %s\n", cveID)
		publishFunc = c.CreateRecord
		action = "create"
	default:
		return fmt.Errorf("publishing a %s record is not supported", state)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s record for %s? (y/N)\n", action, cveID)
	text, _ := reader.ReadString('\n')
	if text != "y\n" {
		fmt.Printf("exiting without %sing record\n", strings.TrimSuffix(action, "e"))
		return nil
	}

	_, err = publishFunc(cveID, toPublish)
	if err != nil {
		return err
	}

	fmt.Printf("successfully %sd record for %s at %s\n", action, cveID, c.WebURL(cveID))

	return nil
}

func handleDeleted(existing *cve5.CVERecord, toPublish *cve5.Containers, filename string) bool {
	deleted := findDeleted(existing.Containers.CNAContainer.References, toPublish.CNAContainer.References)
	if len(deleted) == 0 {
		return false
	}
	goID := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	yamlReportFile := fmt.Sprintf("data/reports/%s.yaml", goID)
	// To preserve an externally-added reference, add it to
	// cve_metadata.references. An example is GO-2022-0476.
	// This warning may be spurious if a reference is deleted from
	// a YAML report - in this case it should be ignored.
	fmt.Printf(
		`!! WARNING !!
updating record would delete %[1]d reference(s) that may have been added by the CVE program;
to preserve these references, add references to %[2]s and run "vulnreport fix %[2]s":

cve_metadata:
    ...
    references:
        ...
        - %[3]s

only update now if this warning is spurious (i.e., the records were deleted on purpose)
`, len(deleted), yamlReportFile, strings.Join(deleted, "\n        - "))

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("try to auto-add missing refs? (y/N)\n")
	text, _ := reader.ReadString('\n')
	if text != "y\n" {
		return false
	}

	if err := addMissing(yamlReportFile, deleted); err != nil {
		fmt.Println("ERROR: could not add missing refs: ", err)
		return false
	}

	fmt.Printf("successfully added %d missing refs\n", len(deleted))
	return true
}

func addMissing(yamlFile string, missing []string) error {
	r, err := report.Read(yamlFile)
	if err != nil {
		return err
	}
	r.CVEMetadata.References = append(r.CVEMetadata.References, missing...)
	if err := r.Write(yamlFile); err != nil {
		return err
	}
	cve, err := cve5.FromReport(r)
	if err != nil {
		return err
	}
	return database.WriteJSON(r.CVEFilename(), cve, true)
}

// findDeleted returns a list of URLs in oldRefs that are not in newRefs.
func findDeleted(oldRefs []cve5.Reference, newRefs []cve5.Reference) (deleted []string) {
	m := make(map[string]bool)
	for _, r := range newRefs {
		m[r.URL] = true
	}
	for _, r := range oldRefs {
		if !m[r.URL] {
			deleted = append(deleted, r.URL)
		}
	}
	return deleted
}

func list(c *cve5.Client, lf *cve5.ListOptions) error {
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
