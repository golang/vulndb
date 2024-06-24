// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package proxy provides a client and utilities for accessing the Go module proxy.
// Queries about the Go standard library and toolchain are not supported.
package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	urlpath "path"
	"sort"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/version"
)

// Client is a client for reading from the proxy.
//
// It uses a simple in-memory cache that does not expire,
// which is acceptable because we use this Client in a short-lived
// context (~1 day at most, in the case of the worker, and a few seconds
// in the case of the vulnreport command), and module/version data does
// not change often enough to be a problem for our use cases.
type Client struct {
	*http.Client
	url    string
	cache  *cache
	errLog *errLog // for testing
}

func NewClient(c *http.Client, url string) *Client {
	return &Client{
		Client: c,
		url:    url,
		cache:  newCache(),
		errLog: newErrLog(),
	}
}

const ProxyURL = "https://proxy.golang.org"

func NewDefaultClient() *Client {
	proxyURL := ProxyURL
	if proxy, ok := os.LookupEnv("GOPROXY"); ok {
		proxyURL = proxy
	}
	return NewClient(http.DefaultClient, proxyURL)
}

func (c *Client) lookup(urlSuffix string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", c.url, urlSuffix)
	if b, found := c.cache.get(urlSuffix); found {
		return b, nil
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		c.errLog.set(urlSuffix, resp.StatusCode)
		return nil, fmt.Errorf("HTTP GET /%s returned status %v", urlSuffix, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	c.cache.set(urlSuffix, b)
	return b, nil
}

func (c *Client) list(path string) ([]byte, error) {
	escaped, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	return c.lookup(fmt.Sprintf("%s/@v/list", escaped))
}

func (c *Client) latest(path string) ([]byte, error) {
	escaped, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	return c.lookup(fmt.Sprintf("%s/@latest", escaped))
}

func (c *Client) info(path string, ver string) ([]byte, error) {
	// module.Check does not accept commit hash versions,
	// but the proxy does (for "info" requests).
	if !version.IsCommitHash(ver) {
		if err := module.Check(path, vv(ver)); err != nil {
			return nil, err
		}
	}
	ep, ev, err := escapePathAndVersion(path, ver)
	if err != nil {
		return nil, err
	}
	return c.lookup(fmt.Sprintf("%s/@v/%v.info", ep, ev))
}

func (c *Client) mod(path string, ver string) ([]byte, error) {
	if err := module.Check(path, vv(ver)); err != nil {
		return nil, err
	}
	ep, ev, err := escapePathAndVersion(path, ver)
	if err != nil {
		return nil, err
	}
	return c.lookup(fmt.Sprintf("%s/@v/%v.mod", ep, ev))
}

// escapePathAndVersion escapes the module path and version.
func escapePathAndVersion(path, ver string) (ePath, eVersion string, err error) {
	vv := vv(ver)
	if ePath, err = module.EscapePath(path); err != nil {
		return "", "", err
	}
	if eVersion, err = module.EscapeVersion(vv); err != nil {
		return "", "", err
	}
	return ePath, eVersion, err
}

func vv(ver string) string {
	// The proxy does not expect a "v" prefix for commit hashes.
	if version.IsCommitHash(ver) {
		return ver
	}
	return "v" + ver
}

// CanonicalAtLatest finds the canonical module path for the given module path
// at the latest version.
func (c *Client) CanonicalAtLatest(path string) (_ string, err error) {
	v, err := c.Latest(path)
	if err != nil {
		return "", nil
	}
	return c.CanonicalModulePath(path, v)
}

func (c *Client) CanonicalModulePath(path, version string) (_ string, err error) {
	b, err := c.mod(path, version)
	if err != nil {
		return "", err
	}
	m, err := modfile.ParseLax("go.mod", b, nil)
	if err != nil {
		return "", err
	}
	if m.Module == nil {
		return "", fmt.Errorf("unable to retrieve module information for %s", path)
	}
	return m.Module.Mod.Path, nil
}

// ModuleExistsAtTaggedVersion returns whether the given module path exists
// at the given version.
// The module need not be canonical, but the version must be an unprefixed
// canonical tagged version (e.g. 1.2.3 or 1.2.3+incompatible).
func (c *Client) ModuleExistsAtTaggedVersion(path, version string) bool {
	// Use this strategy to take advantage of caching.
	// Some reports would cause this function to be called for many versions
	// on the same module.
	vs, err := c.versions(path)
	if err != nil {
		return false
	}
	return slices.Contains(vs, version)
}

// CanonicalModuleVersion returns the canonical version string (with no leading "v" prefix)
// for the given module path and version string.
func (c *Client) CanonicalModuleVersion(path, ver string) (_ string, err error) {
	b, err := c.info(path, ver)
	if err != nil {
		return "", err
	}
	var val map[string]any
	if err := json.Unmarshal(b, &val); err != nil {
		return "", err
	}
	v, ok := val["Version"].(string)
	if !ok {
		return "", fmt.Errorf("unable to retrieve canonical version for %s", ver)
	}
	return version.TrimPrefix(v), nil
}

// Latest returns the latest version of the module, with no leading "v"
// prefix.
func (c *Client) Latest(path string) (string, error) {
	b, err := c.latest(path)
	if err != nil {
		return "", err
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	ver, ok := v["Version"].(string)
	if !ok {
		return "", fmt.Errorf("unable to retrieve latest version for %s", path)
	}
	return version.TrimPrefix(ver), nil
}

// Versions returns a list of module versions (with no leading "v" prefix),
// sorted in ascending order.
func (c *Client) Versions(path string) ([]string, error) {
	vs, err := c.versions(path)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(vs, func(i, j int) bool {
		return version.Before(vs[i], vs[j])
	})
	return vs, nil
}

// versions returns an unsorted list of module versions (with no leading "v" prefix).
func (c *Client) versions(path string) ([]string, error) {
	b, err := c.list(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var vs []string
	for _, v := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		vs = append(vs, version.TrimPrefix(v))
	}
	return vs, nil
}

var errNoModuleFound = errors.New("no module found")

// FindModule returns the longest directory prefix of path that
// is a module, or "" if no such prefix is found.
func (c *Client) FindModule(path string) (modPath string, err error) {
	derrors.Wrap(&err, "FindModule(%s)", path)

	for candidate := path; candidate != "."; candidate = urlpath.Dir(candidate) {
		if c.ModuleExists(candidate) {
			return candidate, nil
		}
	}

	return "", errNoModuleFound
}

// ModuleExists returns true if path is a recognized module
// with at least one associated version.
func (c *Client) ModuleExists(path string) bool {
	_, err := c.latest(path)
	if err != nil {
		// If latest doesn't work, fall back to checking
		// if list succeeds and is non-empty.
		b, err := c.list(path)
		return err == nil && len(b) != 0
	}
	return true
}

// A simple in-memory cache that never expires.
type cache struct {
	data map[string][]byte
	hits int // for testing
	mu   sync.Mutex
}

func newCache() *cache {
	return &cache{data: make(map[string][]byte)}
}

func (c *cache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if b, ok := c.data[key]; ok {
		c.hits++
		return b, true
	}

	return nil, false
}

func (c *cache) set(key string, val []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = val
}

func (c *cache) getData() map[string][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.data
}
