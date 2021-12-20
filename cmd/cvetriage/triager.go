// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/report"
)

// triager is a map of cveID to the CVE record in our database.
type triager map[string]*cve

// cve represents a CVE.
type cve struct {
	cveschema.CVE

	// state is an internal representation of the CVE state.
	state string

	// modulePath is the module path corresponding to this CVE, if any.
	modulePath string

	// cwe is the CWE for the CVE.
	cwe string

	// links contains links that will be included in the report.
	links report.Links

	// description is a description of the CVE.
	description string

	// isGoVuln reports if the cve is a potential Go vulnerability.
	isGoVuln bool
}

func (c *cve) id() string {
	return c.ID
}

func newTriager(triaged map[string]string) triager {
	t := map[string]*cve{}
	for cveID, state := range triaged {
		t[cveID] = &cve{
			CVE: cveschema.CVE{
				Metadata: cveschema.Metadata{
					ID: cveID,
				},
			},
			state: state,
		}
	}
	return t
}

// add adds a CVE to be tracked by the triager.
func (t triager) add(r *cve) {
	t[r.id()] = r
}

// contains reports whether the triager has already seen this cveID.
func (t triager) contains(cveID string) bool {
	_, ok := t[cveID]
	return ok
}

// totalCVEs reports the total number of CVEs that have been seen by the triager.
func (t triager) totalCVEs() int {
	return len(t)
}

// totalVulns reports the total number of CVEs that are potential Go
// vulnerabilities.
func (t triager) totalVulns() int {
	var count int
	for _, r := range t {
		if r.isGoVuln {
			count += 1
		}
	}
	return count
}
