// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Package genericosv provides utilities for working with generic
// OSV structs (not specialized for Go).
package genericosv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/vulndb/internal/report"
)

// Entry is a a generic OSV entry, not specialized for Go.
type Entry Vulnerability

func NewFetcher() report.Fetcher {
	return &client{http.DefaultClient, "https://api.osv.dev/v1"}
}

// Fetch returns the OSV entry from the osv.dev API for the
// given ID.
func (c *client) Fetch(_ context.Context, id string) (report.Source, error) {
	return c.fetch(id)
}

type client struct {
	*http.Client
	url string
}

func (c *client) fetch(id string) (*Entry, error) {
	url := fmt.Sprintf("%s/vulns/%s", c.url, id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET %s returned unexpected status code %d", url, resp.StatusCode)
	}
	var osv Entry
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &osv); err != nil {
		return nil, err
	}
	return &osv, nil
}
