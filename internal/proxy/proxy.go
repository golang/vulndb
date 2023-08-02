// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package proxy provides utilities for accessing the Go module proxy.
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/vulndb/internal/version"
)

var DefaultClient *Client

// Client is a client for reading from the proxy.
//
// It uses a simple in-memory cache that does not expire,
// which is acceptable because we use this Client in a short-lived
// context (~1 day at most, in the case of the worker, and a few seconds
// in the case of the vulnreport command), and module/version data does
// not change often enough to be a problem for our use cases.
type Client struct {
	*http.Client
	url   string
	cache *cache
}

func init() {
	proxyURL := "https://proxy.golang.org"
	if proxy, ok := os.LookupEnv("GOPROXY"); ok {
		proxyURL = proxy
	}
	DefaultClient = NewClient(http.DefaultClient, proxyURL)
}

func NewClient(c *http.Client, url string) *Client {
	return &Client{
		Client: c,
		url:    url,
		cache:  newCache(),
	}
}

func (c *Client) lookup(urlSuffix string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", c.url, urlSuffix)
	if b, found := c.cache.get(url); found {
		return b, nil
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP GET /%s returned status %v", urlSuffix, resp.Status)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	c.cache.set(url, b)
	return b, nil
}

func CanonicalModulePath(path, version string) (string, error) {
	return DefaultClient.CanonicalModulePath(path, version)
}

func (c *Client) CanonicalModulePath(path, version string) (_ string, err error) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	b, err := c.lookup(fmt.Sprintf("%s/@v/%s.mod", escapedPath, escapedVersion))
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

func CanonicalModuleVersion(path, ver string) (_ string, err error) {
	return DefaultClient.CanonicalModuleVersion(path, ver)
}

// CanonicalModuleVersion returns the canonical version string (with no leading "v" prefix)
// for the given module path and version string.
func (c *Client) CanonicalModuleVersion(path, ver string) (_ string, err error) {
	escaped, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	b, err := c.lookup(fmt.Sprintf("%s/@v/%v.info", escaped, ver))
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

func Latest(path string) (string, error) {
	return DefaultClient.Latest(path)
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

func Versions(path string) ([]string, error) {
	return DefaultClient.Versions(path)
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

func FindModule(path string) string {
	return DefaultClient.FindModule(path)
}

// FindModule returns the longest directory prefix of path that
// is a module, or "" if no such prefix is found.
func (c *Client) FindModule(modPath string) string {
	for candidate := modPath; candidate != "."; candidate = path.Dir(candidate) {
		escaped, err := module.EscapePath(candidate)
		if err != nil {
			return modPath
		}
		if _, err := c.lookup(fmt.Sprintf("%s/@v/list", escaped)); err != nil {
			// Keep looking.
			continue
		}
		return candidate
	}
	return ""
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
