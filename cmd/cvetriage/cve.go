// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/report"
)

const (
	stateReserved        = "Reserved"
	statePublicNotGoVuln = "Public - Not Go Vuln"
	statePublicGoVuln    = "Public - Go Vuln"
)

var errCVEVersionUnsupported = errors.New("unsupported CVE version")

// triageCVE triages the CVE and creates a cve record state.
func triageCVE(c *cveschema.CVE) (_ *cve, err error) {
	defer derrors.Wrap(&err, "cveToIssue(%q)", c.ID)
	if isReservedCVE(c) {
		return createCVE(c, stateReserved, "", false), nil
	}
	switch c.DataVersion {
	case "4.0":
		mp, err := cveModulePath(c)
		if err != nil {
			return nil, err
		}
		if mp == "" {
			return createCVE(c, statePublicNotGoVuln, "", false), nil
		}
		return createCVE(c, statePublicGoVuln, mp, true), nil
	default:
		// TODO(https://golang.org/issue/49289): Add support for v5.0.
		return nil, fmt.Errorf("CVE %q has DataVersion %q: %w", c.ID, c.DataVersion, errCVEVersionUnsupported)
	}
}

// createCVE creates a cve record state from the data provided.
func createCVE(c *cveschema.CVE, state string, mp string, isGoVuln bool) *cve {
	r := &cve{
		CVE:         *c,
		state:       state,
		cwe:         cveCWE(c),
		modulePath:  mp,
		links:       cveLinks(c),
		description: description(c),
		isGoVuln:    isGoVuln,
	}
	return r
}

// isPendingCVE reports if the CVE is still waiting on information and not
// ready to be triaged.
func isReservedCVE(c *cveschema.CVE) bool {
	return c.State == cveschema.StateReserved
}

var vcsHostsWithThreeElementRepoName = map[string]bool{
	"bitbucket.org": true,
	"gitea.com":     true,
	"gitee.com":     true,
	"github.com":    true,
	"gitlab.com":    true,
	"golang.org":    true,
}

var stdlibKeywords = map[string]bool{
	"github.com/golang": true,
	"golang-announce":   true,
	"golang-nuts":       true,
	"golang.org":        true,
}

// cveModulePath returns a Go module path for a CVE, if we can determine what
// it is.
func cveModulePath(c *cveschema.CVE) (_ string, err error) {
	defer derrors.Wrap(&err, "cveModulePath(%q)", c.ID)
	for _, r := range c.References.Data {
		if r.URL == "" {
			continue
		}
		for k := range stdlibKeywords {
			if strings.Contains(r.URL, k) {
				return "Go Standard Library", nil
			}
		}
		for host := range vcsHostsWithThreeElementRepoName {
			if !strings.Contains(r.URL, host) {
				continue
			}
			refURL, err := url.Parse(r.URL)
			if err != nil {
				return "", fmt.Errorf("url.Parse(%q): %v", r.URL, err)
			}
			u := refURL.Host + refURL.Path
			parts := strings.Split(u, "/")
			if len(parts) < 3 {
				continue
			}
			mod := strings.Join(parts[0:3], "/")
			r, err := http.DefaultClient.Get(fmt.Sprintf("https://pkg.go.dev/%s", mod))
			if err != nil {
				return "", err
			}
			if r.StatusCode == http.StatusOK {
				return mod, nil
			}
		}
	}
	return "", nil
}

func cveLinks(c *cveschema.CVE) report.Links {
	var links report.Links
	for _, r := range c.References.Data {
		if links.Commit == "" && strings.Contains(r.URL, "/commit/") {
			links.Commit = r.URL
		} else if links.PR == "" && strings.Contains(r.URL, "/pull/") {
			links.PR = r.URL
		} else {
			links.Context = append(links.Context, r.URL)
		}
	}
	return links
}

func cveCWE(c *cveschema.CVE) string {
	var cwe string
	for _, pt := range c.ProblemType.Data {
		for _, d := range pt.Description {
			if strings.Contains(d.Value, "CWE") {
				cwe = d.Value
			}
		}
	}
	return cwe
}

func description(c *cveschema.CVE) string {
	var ds []string
	for _, d := range c.Description.Data {
		ds = append(ds, d.Value)
	}
	return strings.Join(ds, "| \n ")
}
