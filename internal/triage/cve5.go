// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package triage

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/stdlib"
	"golang.org/x/vulndb/internal/worker/log"
)

type CVE5Triager struct {
	pc *pkgsite.Client
}

func (t *CVE5Triager) AffectsGo(ctx context.Context, cve *cve5.CVERecord) (result *Result, err error) {
	v := cve
	pc := t.pc
	defer func() {
		if err != nil {
			return
		}
		msg := fmt.Sprintf("Triage result for %s", v.SourceID())
		if result == nil {
			log.Debugf(ctx, "%s: not Go vuln", msg)
			return
		}
		log.Debugf(ctx, "%s: is Go vuln:\n%s", msg, result.Reason)
	}()
	for _, rurl := range v.ReferenceURLs() {
		if rurl == "" {
			continue
		}
		refURL, err := url.Parse(rurl)
		if err != nil {
			return nil, fmt.Errorf("url.Parse(%q): %v", rurl, err)
		}
		if strings.Contains(rurl, "golang.org/pkg") {
			mp := strings.TrimPrefix(refURL.Path, "/pkg/")
			return &Result{
				PackagePath: mp,
				ModulePath:  stdlib.ModulePath,
				Reason:      fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
			}, nil
		}
		if gopkgHosts[refURL.Host] {
			mp := strings.TrimPrefix(refURL.Path, "/")
			if stdlib.Contains(mp) {
				return &Result{
					PackagePath: mp,
					ModulePath:  stdlib.ModulePath,
					Reason:      fmt.Sprintf("Reference data URL %q contains path %q", rurl, mp),
				}, nil
			}
			return &Result{
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
				u := pkgsite.URL + "/" + mp
				return &Result{
					ModulePath: mp,
					Reason:     fmt.Sprintf("Reference data URL %q contains path %q; %q returned a status 200", rurl, mp, u),
				}, nil
			}
		}
	}

	// We didn't find a Go package or module path in the reference data. Check
	// secondary heuristics to see if this is a Go related CVE.
	for _, rurl := range v.ReferenceURLs() {
		// Example CVE containing snyk.io URL:
		// https://github.com/CVEProject/cvelist/blob/899bba20d62eb73e04d1841a5ff04cd6225e1618/2020/7xxx/CVE-2020-7668.json#L52.
		if strings.Contains(rurl, snykIdentifier) {
			return &Result{
				ModulePath: unknownPath,
				Reason:     fmt.Sprintf("Reference data URL %q contains %q", rurl, snykIdentifier),
			}, nil
		}

		// Check for reference data indicating that this is related to the Go
		// project.
		for _, k := range stdlibReferenceDataKeywords {
			if strings.Contains(rurl, k) {
				return &Result{
					ModulePath: stdlib.ModulePath,
					Reason:     fmt.Sprintf("Reference data URL %q contains %q", rurl, k),
				}, nil
			}
		}
	}
	return nil, nil
}
