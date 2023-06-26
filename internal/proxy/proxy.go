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
	"sync"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
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
		return nil, fmt.Errorf("http.Get(%q) returned status %v", url, resp.Status)
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

func CanonicalModuleVersion(path, version string) (_ string, err error) {
	return DefaultClient.CanonicalModuleVersion(path, version)
}

func (c *Client) CanonicalModuleVersion(path, version string) (_ string, err error) {
	escaped, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	b, err := c.lookup(fmt.Sprintf("%s/@v/%v.info", escaped, version))
	if err != nil {
		return "", err
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	ver, ok := v["Version"].(string)
	if !ok {
		return "", fmt.Errorf("unable to retrieve canonical version for %s", version)
	}
	return ver, nil
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
