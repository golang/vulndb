// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkgsite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"golang.org/x/vulndb/internal/worker/log"
)

type Client struct {
	url   string
	cache *cache
}

func Default() *Client {
	return New(pkgsiteURL)
}

func New(url string) *Client {
	return &Client{
		url:   url,
		cache: newCache(),
	}
}

func (pc *Client) SetKnownModules(known []string) {
	pc.cache.setKnownModules(known)
}

// Limit pkgsite requests to this many per second.
const pkgsiteQPS = 5

var (
	// The limiter used to throttle pkgsite requests.
	// The second argument to rate.NewLimiter is the burst, which
	// basically lets you exceed the rate briefly.
	pkgsiteRateLimiter = rate.NewLimiter(rate.Every(time.Duration(1000/float64(pkgsiteQPS))*time.Millisecond), 3)
)

var pkgsiteURL = "https://pkg.go.dev"

// Known reports whether pkgsite knows that modulePath actually refers
// to a module.
func (pc *Client) Known(ctx context.Context, modulePath string) (bool, error) {
	found, ok := pc.cache.lookup(modulePath)
	if ok {
		return found, nil
	}

	// Pause to maintain a max QPS.
	if err := pkgsiteRateLimiter.Wait(ctx); err != nil {
		return false, err
	}
	start := time.Now()

	url := pc.url + "/mod/" + modulePath
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
	pc.cache.add(modulePath, known)
	return known, nil
}

func (pc *Client) URL() string {
	return pc.url
}

func readKnown(r io.Reader) (map[string]bool, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("no data")
	}
	seen := make(map[string]bool)
	if err := json.Unmarshal(b, &seen); err != nil {
		return nil, err
	}
	return seen, nil
}

func (c *cache) writeKnown(w io.Writer) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	b, err := json.MarshalIndent(c.seen, "", "   ")
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// CacheFile returns a default cache file that can be used as an input
// to TestClient.
//
// For testing.
func CacheFile(t *testing.T) (*os.File, error) {
	filename := filepath.Join("testdata", "pkgsite", t.Name()+".json")
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return nil, err
	}

	// If the file doesn't exist, or is empty, add an empty map.
	fi, err := os.Stat(filename)
	if err != nil || fi.Size() == 0 {
		if err := os.WriteFile(filename, []byte("{}\n"), 0644); err != nil {
			return nil, err
		}
	}

	f, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	return f, nil
}

// TestClient returns a pkgsite client that talks to either
// a fake server or the real pkg.go.dev, depending on the useRealPkgsite value.
//
// For testing.
func TestClient(t *testing.T, useRealPkgsite bool, rw io.ReadWriter) (*Client, error) {
	if useRealPkgsite {
		c := Default()
		t.Cleanup(func() {
			err := c.cache.writeKnown(rw)
			if err != nil {
				t.Error(err)
			}
		})
		return c, nil
	}
	known, err := readKnown(rw)
	if err != nil {
		return nil, fmt.Errorf("could not read known modules: %w", err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modulePath := strings.TrimPrefix(r.URL.Path, "/mod/")
		if !known[modulePath] {
			http.Error(w, "unknown", http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return New(s.URL), nil
}

type cache struct {
	mu sync.Mutex
	// Module paths already seen.
	seen map[string]bool
	// Does the cache contain all known modules?
	complete bool
}

func newCache() *cache {
	return &cache{
		seen:     make(map[string]bool),
		complete: false,
	}
}

func (c *cache) setKnownModules(known []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, km := range known {
		c.seen[km] = true
	}
	c.complete = true
}

func (c *cache) lookup(modulePath string) (known bool, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// In the cache.
	if known, ok := c.seen[modulePath]; ok {
		return known, true
	}

	// Not in the cache, but the cache is complete, so this
	// module is not known.
	if c.complete {
		return false, true
	}

	// We can't make a statement about this module.
	return false, false
}

func (c *cache) add(modulePath string, known bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seen[modulePath] = known
}
