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
	"time"

	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/report"
)

// Entry is a a generic OSV entry, not specialized for Go.
type Entry Vulnerability

func NewFetcher() report.Fetcher {
	return &osvDevClient{http.DefaultClient, osvDevAPI}
}

func NewGHSAFetcher(gc ghsaClient) report.Fetcher {
	return &githubClient{Client: http.DefaultClient, gc: gc, url: githubAPI}
}

const (
	osvDevAPI = "https://api.osv.dev/v1/vulns"
	githubAPI = "https://api.github.com/advisories"
)

// Fetch returns the OSV entry from the osv.dev API for the given ID.
func (c *osvDevClient) Fetch(_ context.Context, id string) (report.Source, error) {
	url := fmt.Sprintf("%s/%s", c.url, id)
	return get[Entry](c.Client, url)
}

type githubClient struct {
	*http.Client
	url string

	gc ghsaClient
}

// Fetch returns the OSV entry directly from the Github advisory repo
// (https://github.com/github/advisory-database).
//
// This unfortunately requires two HTTP requests, the first to figure
// out the published date of the GHSA, and the second to fetch the OSV.
//
// This is because the direct Github API returns a non-OSV format,
// and the OSV files are available in a Github repo whose directory
// structure is determined by the published year and month of each GHSA.
func (c *githubClient) Fetch(ctx context.Context, id string) (report.Source, error) {
	sa, err := c.gc.FetchGHSA(ctx, id)
	if err != nil {
		return nil, err
	}
	pub := sa.PublishedAt
	if pub.IsZero() {
		return nil, fmt.Errorf("could not determine direct URL for GHSA OSV (need published date)")
	}
	githubURL := toGithubURL(id, pub)
	return get[Entry](c.Client, githubURL)
}

type ghsaClient interface {
	FetchGHSA(context.Context, string) (*ghsa.SecurityAdvisory, error)
}

func toGithubURL(id string, published time.Time) string {
	const base = "https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed"
	year := published.Year()
	month := published.Month()
	return fmt.Sprintf("%s/%d/%02d/%s/%s.json", base, year, month, id, id)
}

type osvDevClient struct {
	*http.Client
	url string
}

func get[T any](cli *http.Client, url string) (*T, error) {
	var zero *T
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("HTTP GET %s returned unexpected status code %d", url, resp.StatusCode)
	}
	v := new(T)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return zero, err
	}
	return v, nil
}

func (e *Entry) AffectsGo() bool {
	for _, a := range e.Affected {
		if a.Package.Ecosystem == EcosystemGo {
			return true
		}
	}
	return false
}

func (e *Entry) IsWithdrawn() bool {
	return !e.Withdrawn.IsZero()
}
