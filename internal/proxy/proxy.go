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
	"path/filepath"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// TODO(https://go.dev/issues/60275): Cache proxy lookups.

var proxyURL = "https://proxy.golang.org"

func init() {
	if proxy, ok := os.LookupEnv("GOPROXY"); ok {
		proxyURL = proxy
	}
}

func lookup(urlSuffix string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", proxyURL, urlSuffix)
	resp, err := http.Get(url)
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
	return b, nil
}

func CanonicalModulePath(path, version string) (_ string, err error) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	b, err := lookup(fmt.Sprintf("%s/@v/%s.mod", escapedPath, escapedVersion))
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

func CanonicalModuleVersion(path, version string) (_ string, err error) {
	escaped, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	b, err := lookup(fmt.Sprintf("%s/@v/%v.info", escaped, version))
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

// FindModule returns the longest directory prefix of path that
// is a module, or "" if no such prefix is found.
func FindModule(path string) string {
	for candidate := path; candidate != "."; candidate = filepath.Dir(candidate) {
		escaped, err := module.EscapePath(candidate)
		if err != nil {
			return path
		}
		if _, err := lookup(fmt.Sprintf("%s/@v/list", escaped)); err != nil {
			// Keep looking.
			continue
		}
		return candidate
	}
	return ""
}
