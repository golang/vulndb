// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/event"
	"golang.org/x/time/rate"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
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

const (
	stdlibPath  = "Go Standard Library (package not identified)"
	unknownPath = "Path is unknown"
)

// TriageCVE reports whether the CVE refers to a Go module.
func TriageCVE(ctx context.Context, c *cveschema.CVE, pkgsiteURL string) (_ *triageResult, err error) {
	defer derrors.Wrap(&err, "triageCVE(%q)", c.ID)
	switch c.DataVersion {
	case "4.0":
		return triageV4CVE(ctx, c, pkgsiteURL)
	default:
		// TODO(https://golang.org/issue/49289): Add support for v5.0.
		return nil, fmt.Errorf("CVE %q has DataVersion %q: %w", c.ID, c.DataVersion, errCVEVersionUnsupported)
	}
}

type triageResult struct {
	modulePath string
	stdlib     bool
	reason     string
}

// gopkgHosts are hostnames for popular Go package websites.
var gopkgHosts = map[string]bool{
	"godoc.org":  true,
	"pkg.go.dev": true,
}

const snykIdentifier = "snyk.io/vuln/SNYK-GOLANG"

// triageV4CVE triages a CVE following schema v4.0 and returns the result.
func triageV4CVE(ctx context.Context, c *cveschema.CVE, pkgsiteURL string) (_ *triageResult, err error) {
	defer derrors.Wrap(&err, "triageV4CVE(ctx, %q, %q)", c.ID, pkgsiteURL)
	for _, r := range c.References.Data {
		if r.URL == "" {
			continue
		}
		refURL, err := url.Parse(r.URL)
		if err != nil {
			return nil, fmt.Errorf("url.Parse(%q): %v", r.URL, err)
		}
		if strings.Contains(r.URL, "golang.org/pkg") {
			mp := strings.TrimPrefix(refURL.Path, "/pkg/")
			return &triageResult{
				modulePath: mp,
				stdlib:     true,
				reason:     fmt.Sprintf("Reference data URL %q contains path %q", r.URL, mp),
			}, nil
		}
		if gopkgHosts[refURL.Host] {
			mp := strings.TrimPrefix(refURL.Path, "/")
			return &triageResult{
				modulePath: mp,
				stdlib:     stdlibContains(mp),
				reason:     fmt.Sprintf("Reference data URL %q contains path %q", r.URL, mp),
			}, nil
		}
		modpaths := candidateModulePaths(refURL.Host + refURL.Path)
		for _, mp := range modpaths {
			known, err := knownToPkgsite(ctx, pkgsiteURL, mp)
			if err != nil {
				return nil, err
			}
			if known {
				u := pkgsiteURL + "/" + mp
				return &triageResult{
					modulePath: mp,
					reason:     fmt.Sprintf("Reference data URL %q contains path %q; %q returned a status 200", r.URL, mp, u),
				}, nil
			}
		}
	}

	// We didn't find a Go package or module path in the reference data. Check
	// secondary heuristics to see if this is a Go related CVE.
	for _, r := range c.References.Data {
		// Example CVE containing snyk.io URL:
		// https://github.com/CVEProject/cvelist/blob/899bba20d62eb73e04d1841a5ff04cd6225e1618/2020/7xxx/CVE-2020-7668.json#L52.
		if strings.Contains(r.URL, snykIdentifier) {
			return &triageResult{
				modulePath: unknownPath,
				reason:     fmt.Sprintf("Reference data URL %q contains %q", r.URL, snykIdentifier),
			}, nil
		}

		// Check for reference data indicating that this is related to the Go
		// project.
		for _, k := range stdlibReferenceDataKeywords {
			if strings.Contains(r.URL, k) {
				return &triageResult{
					modulePath: stdlibPath,
					stdlib:     true,
					reason:     fmt.Sprintf("Reference data URL %q contains %q", r.URL, k),
				}, nil
			}
		}
	}
	return nil, nil
}

// Limit pkgsite requests to this many per second.
const pkgsiteQPS = 5

var (
	// The limiter used to throttle pkgsite requests.
	// The second argument to rate.NewLimiter is the burst, which
	// basically lets you exceed the rate briefly.
	pkgsiteRateLimiter = rate.NewLimiter(rate.Every(time.Duration(1000/float64(pkgsiteQPS))*time.Millisecond), 3)

	// Cache of module paths already seen.
	seenModulePath = map[string]bool{}
	// Does seenModulePath contain all known modules?
	cacheComplete = false
)

// SetKnownModules provides a list of all known modules,
// so that no requests need to be made to pkg.go.dev.
func SetKnownModules(mods []string) {
	for _, m := range mods {
		seenModulePath[m] = true
	}
	cacheComplete = true
}

// knownToPkgsite reports whether pkgsite knows that modulePath actually refers
// to a module.
func knownToPkgsite(ctx context.Context, baseURL, modulePath string) (bool, error) {
	// If we've seen it before, no need to call.
	if b, ok := seenModulePath[modulePath]; ok {
		return b, nil
	}
	if cacheComplete {
		return false, nil
	}
	// Pause to maintain a max QPS.
	if err := pkgsiteRateLimiter.Wait(ctx); err != nil {
		return false, err
	}
	start := time.Now()

	url := baseURL + "/mod/" + modulePath
	res, err := http.Head(url)
	var status string
	if err == nil {
		status = strconv.Quote(res.Status)
	}
	log.Info(ctx, "HEAD "+url,
		event.Value("latency", time.Since(start)),
		event.String("status", status),
		event.Value("error", err))
	if err != nil {
		return false, err
	}
	known := res.StatusCode == http.StatusOK
	seenModulePath[modulePath] = known
	return known, nil
}
