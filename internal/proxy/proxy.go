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

func escapePathAndVersion(path, ver string) (ePath, eVersion string, err error) {
	ePath, err = module.EscapePath(path)
	if err != nil {
		return "", "", err
	}
	if version.IsCommitHash(ver) {
		return ePath, ver, nil
	}
	eVersion, err = module.EscapeVersion("v" + ver)
	if err != nil {
		return "", "", err
	}
	if err := module.Check(ePath, eVersion); err != nil {
		return "", "", err
	}
	return ePath, eVersion, err
}

func (c *Client) CanonicalModulePath(path, version string) (_ string, err error) {
	ep, ev, err := escapePathAndVersion(path, version)
	if err != nil {
		return "", err
	}
	b, err := c.lookup(fmt.Sprintf("%s/@v/%s.mod", ep, ev))
	if err != nil {
		return "", err
	}
	m, err := modfile.ParseLax("go.mod", b, nil)
	if err != nil {
		return "", err
	}
	if m.Module == nil {
		return "", fmt.Errorf("unable to retrieve module information for %s, %s", path, string(b))
	}
	return m.Module.Mod.Path, nil
}

// CanonicalModuleVersion returns the canonical version string (with no leading "v" prefix)
// for the given module path and version string.
func (c *Client) CanonicalModuleVersion(path, ver string) (_ string, err error) {
	ep, ev, err := escapePathAndVersion(path, ver)
	if err != nil {
		return "", err
	}
	b, err := c.lookup(fmt.Sprintf("%s/@v/%v.info", ep, ev))
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
	escaped, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	b, err := c.lookup(fmt.Sprintf("%s/@latest", escaped))
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
	escaped, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	b, err := c.lookup(fmt.Sprintf("%s/@v/list", escaped))
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
	sort.SliceStable(vs, func(i, j int) bool {
		return version.Before(vs[i], vs[j])
	})
	return vs, nil
}

var errNoModuleFound = errors.New("no module found")

// FindModule returns the longest directory prefix of path that
// is a module, or "" if no such prefix is found.
func (c *Client) FindModule(path string) (modPath string, err error) {
	derrors.Wrap(&err, "FindModule(%s)", path)

	escaped, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}

	for candidate := escaped; candidate != "."; candidate = urlpath.Dir(candidate) {
		if c.moduleExists(candidate) {
			unescaped, err := module.UnescapePath(candidate)
			if err != nil {
				return "", err
			}
			return unescaped, nil
		}
	}

	return "", errNoModuleFound
}

// ModuleExists returns true if modPath is a recognized module.
func (c *Client) ModuleExists(modPath string) bool {
	escaped, err := module.EscapePath(modPath)
	if err != nil {
		return false
	}
	return c.moduleExists(escaped)
}

func (c *Client) moduleExists(escaped string) bool {
	_, err := c.lookup(fmt.Sprintf("%s/@v/list", escaped))
	return err == nil
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
