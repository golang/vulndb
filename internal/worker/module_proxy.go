// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/net/context/ctxhttp"
)

// Convenience functions for accessing the Go module proxy.

const proxyURL = "https://proxy.golang.org"

// latestVersion returns the version of modulePath provided by the proxy's "@latest"
// endpoint.
func latestVersion(ctx context.Context, proxyURL, modulePath string) (string, error) {
	body, err := proxyRequest(ctx, proxyURL, modulePath, "/@latest")
	if err != nil {
		return "", err
	}

	var info struct {
		Version string
		Time    time.Time
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", err
	}
	return info.Version, nil
}

// latestTaggedVersion returns the latest (largest in the semver sense) tagged
// version of modulePath, as determined by the module proxy's "list" endpoint.
// It returns ("", nil) if there are no tagged versions.
func latestTaggedVersion(ctx context.Context, proxyURL, modulePath string) (string, error) {
	body, err := proxyRequest(ctx, proxyURL, modulePath, "/@v/list")
	if err != nil {
		return "", err
	}
	vs := strings.Split(string(bytes.TrimSpace(body)), "\n")
	if len(vs) == 0 {
		return "", nil
	}
	sort.Slice(vs, func(i, j int) bool { return semver.Compare(vs[i], vs[j]) > 0 })
	return vs[0], nil
}

func moduleZip(ctx context.Context, proxyURL, modulePath, version string) (*zip.Reader, error) {
	ev, err := module.EscapeVersion(version)
	if err != nil {
		return nil, err
	}
	body, err := proxyRequest(ctx, proxyURL, modulePath, fmt.Sprintf("/@v/%s.zip", ev))
	if err != nil {
		return nil, err
	}
	return zip.NewReader(bytes.NewReader(body), int64(len(body)))
}

func proxyRequest(ctx context.Context, proxyURL, modulePath, suffix string) ([]byte, error) {
	ep, err := module.EscapePath(modulePath)
	if err != nil {
		return nil, fmt.Errorf("module path %v: %w", modulePath, err)
	}
	url := fmt.Sprintf("%s/%s%s", proxyURL, ep, suffix)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := ctxhttp.Do(ctx, http.DefaultClient, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", url, res.StatusCode)
	}
	return io.ReadAll(res.Body)
}
