// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cveutils

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/worker/log"
)

var errCVEVersionUnsupported = errors.New("unsupported CVE version")

// stdlibReferenceDataKeywords are words found in the reference data URL that
// indicate the CVE is about the standard library or a Go x-repo owned by the
// Go team.
var stdlibReferenceDataKeywords = []string{
	"github.com/golang",
	"golang.org",
	// from https://groups.google.com/g/golang-announce.
	"golang-announce",
	// from https://groups.google.com/g/golang-nuts.
	"golang-nuts",
}

const unknownPath = "Path is unknown"

// TriageCVE reports whether the CVE refers to a Go module.
func TriageCVE(ctx context.Context, c CVE, pc *pkgsite.Client) (_ *TriageResult, err error) {
	defer derrors.Wrap(&err, "cveutils.TriageCVE(%q)", c.SourceID())
	return triageCVE(ctx, c, pc)
}

type TriageResult struct {
	ModulePath  string
	PackagePath string
	Reason      string
}

// gopkgHosts are hostnames for popular Go package websites.
var gopkgHosts = map[string]bool{
	"godoc.org":  true,
	"pkg.go.dev": true,
}

const snykIdentifier = "snyk.io/vuln/SNYK-GOLANG"

// nonGoModules are paths that return a 200 on pkg.go.dev, but do not contain
// Go code. However, these libraries often have CVEs that are false positive for
// a Go vuln.
var notGoModules = map[string]bool{
	"github.com/channelcat/sanic":            true, // python library
	"github.com/rapid7/metasploit-framework": true, // ruby library
	"github.com/tensorflow/tensorflow":       true, // python library
	"gitweb.gentoo.org/repo/gentoo.git":      true, // ebuild
	"qpid.apache.org":                        true, // C, python, & Java library

	// vulnerability in tool, not importable package
	"github.com/grafana/grafana":          true,
	"github.com/sourcegraph/sourcegraph":  true,
	"gitlab.com/gitlab-org/gitlab-runner": true,
	"github.com/gravitational/teleport":   true,
}

type CVE interface {
	SourceID() string
	ReferenceURLs() []string
}

// triageCVE triages a CVE and returns the result.
func triageCVE(ctx context.Context, c CVE, pc *pkgsite.Client) (result *TriageResult, err error) {
	defer func() {
		if err != nil {
			return
		}
		msg := fmt.Sprintf("Triage result for %s", c.SourceID())
		if result == nil {
			log.Debugf(ctx, "%s: not Go vuln", msg)
			return
		}
		log.Debugf(ctx, "%s: is Go vuln:\n%s", msg, result.Reason)
	}()
	for _, rurl := range c.ReferenceURLs() {
		if rurl == "" {
			continue
		}
		refURL, err := url.Parse(rurl)
		if err != nil {
			return nil, fmt.Errorf("url.Parse(%q): %v", rurl, err)
		}
		if strings.Contains(rurl, "golang.org/pkg") {
			mp := strings.TrimPrefix(refURL.Path, "/pkg/")
			return &TriageResult{
				PackagePath: mp,
				ModulePath:  stdlib.ModulePath,
				Reason:      fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
			}, nil
		}
		if gopkgHosts[refURL.Host] {
			mp := strings.TrimPrefix(refURL.Path, "/")
			if stdlib.Contains(mp) {
				return &TriageResult{
					PackagePath: mp,
					ModulePath:  stdlib.ModulePath,
					Reason:      fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
				}, nil
			}
			return &TriageResult{
				ModulePath: mp,
				Reason:     fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
			}, nil
		}
		modpaths := candidateModulePaths(refURL.Host + refURL.Path)
		for _, mp := range modpaths {
			if notGoModules[mp] {
				continue
			}
			known, err := pc.KnownModule(ctx, mp)
			if err != nil {
				return nil, err
			}
			if known {
				u := pc.URL() + "/" + mp
				return &TriageResult{
					ModulePath: mp,
					Reason:     fmt.Sprintf("Reference data URL %q contains path %q; %q returned a status 200", rurl, mp, u),
				}, nil
			}
		}
	}

	// We didn't find a Go package or module path in the reference data. Check
	// secondary heuristics to see if this is a Go related CVE.
	for _, rurl := range c.ReferenceURLs() {
		// Example CVE containing snyk.io URL:
		// https://github.com/CVEProject/cvelist/blob/899bba20d62eb73e04d1841a5ff04cd6225e1618/2020/7xxx/CVE-2020-7668.json#L52.
		if strings.Contains(rurl, snykIdentifier) {
			return &TriageResult{
				ModulePath: unknownPath,
				Reason:     fmt.Sprintf("Reference data URL %q contains %q", rurl, snykIdentifier),
			}, nil
		}

		// Check for reference data indicating that this is related to the Go
		// project.
		for _, k := range stdlibReferenceDataKeywords {
			if strings.Contains(rurl, k) {
				return &TriageResult{
					ModulePath: stdlib.ModulePath,
					Reason:     fmt.Sprintf("Reference data URL %q contains %q", rurl, k),
				}, nil
			}
		}
	}
	return nil, nil
}

func GetAliasGHSAs(c CVE) []string {
	var ghsas []string
	for _, rurl := range c.ReferenceURLs() {
		if ghsa := idstr.FindGHSA(rurl); ghsa != "" {
			ghsas = append(ghsas, ghsa)
		}
	}
	return ghsas
}
