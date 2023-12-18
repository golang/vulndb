// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cveutils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"golang.org/x/vulndb/internal/worker/log"
)

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

var pkgsiteURL = "https://pkg.go.dev"

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
	log.With(
		"latency", time.Since(start),
		"status", status,
		"error", err,
	).Debugf(ctx, "checked if %s is known to pkgsite at HEAD", url)
	if err != nil {
		return false, err
	}
	known := res.StatusCode == http.StatusOK
	seenModulePath[modulePath] = known
	return known, nil
}

// GetPkgsiteURL returns a URL to either a fake server or the real pkg.go.dev,
// depending on the useRealPkgsite value.
//
// For testing.
func GetPkgsiteURL(t *testing.T, useRealPkgsite bool) string {
	if useRealPkgsite {
		return pkgsiteURL
	}
	// Start a test server that recognizes anything from golang.org and bitbucket.org/foo/bar/baz.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modulePath := strings.TrimPrefix(r.URL.Path, "/mod/")
		if !strings.HasPrefix(modulePath, "golang.org/") &&
			!strings.HasPrefix(modulePath, "bitbucket.org/foo/bar/baz") {
			http.Error(w, "unknown", http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s.URL
}
