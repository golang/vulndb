// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"

	"golang.org/x/vulndb/internal/cveclient"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/proxy"
)

// Source represents a vulnerability format (e.g., GHSA, CVE)
// that can be converted to our Report format.
type Source interface {
	// SourceID returns the ID of the source.
	// For example, the GHSA or CVE id.
	SourceID() string
	ToReport(goID string, modulePath string, pc *proxy.Client) *Report
}

func New(src Source, goID string, modulePath string, pc *proxy.Client) *Report {
	return src.ToReport(goID, modulePath, pc)
}

type Fetcher interface {
	Fetch(ctx context.Context, id string) (Source, error)
}

type cve5 struct {
	*cveschema5.CVERecord
}

var _ Source = &cve5{}

func (c *cve5) ToReport(goID, modulePath string, pc *proxy.Client) *Report {
	return CVE5ToReport(c.CVERecord, goID, modulePath, pc)
}

func (c *cve5) SourceID() string {
	return c.Metadata.ID
}

type cve5Fetcher struct{}

func CVE5Fetcher() Fetcher {
	return &cve5Fetcher{}
}

func (_ *cve5Fetcher) Fetch(ctx context.Context, id string) (Source, error) {
	cve, err := cveclient.Fetch(id)
	if err != nil {
		return nil, err
	}
	return &cve5{CVERecord: cve}, nil
}

// cve4 is a wrapper for a CVE in CVE JSON 4.0 (legacy) format.
//
// Note: Fetch is not implemented for CVE4, as it is a legacy format
// which will be phased out soon.
type cve4 cveschema.CVE

var _ Source = &cve4{}

func (c *cve4) ToReport(goID, modulePath string, pc *proxy.Client) *Report {
	cve := cveschema.CVE(*c)
	return CVEToReport(&cve, goID, modulePath, pc)
}

func (c *cve4) SourceID() string {
	return c.ID
}

// legacyGHSA is a wrapper for a GHSA in the format retrievable
// via the Github GraphQL API.
//
// We are planning to phase this out in favor of the Github OSV format,
// but some of our processes still rely on this format.
type legacyGHSA struct {
	*ghsa.SecurityAdvisory
}

var _ Source = &legacyGHSA{}

func (g *legacyGHSA) ToReport(goID, modulePath string, pc *proxy.Client) *Report {
	r := GHSAToReport(g.SecurityAdvisory, modulePath, pc)
	r.ID = goID
	return r
}

func (g *legacyGHSA) SourceID() string {
	return g.ID
}

type legacyGHSAFetcher struct {
	*ghsa.Client
}

func LegacyGHSAFetcher(c *ghsa.Client) Fetcher {
	return &legacyGHSAFetcher{
		Client: c,
	}
}

func (g *legacyGHSAFetcher) Fetch(ctx context.Context, id string) (Source, error) {
	fetched, err := g.FetchGHSA(ctx, id)
	if err != nil {
		return nil, err
	}
	return &legacyGHSA{
		SecurityAdvisory: fetched,
	}, err
}

// original represents an original report created from scratch by the Go Security Team.
//
// This is used for standard library & toolchain reports, or in cases where the
// source report cannot be retrieved automatically.
type original struct{}

var _ Source = &original{}

func Original() Source {
	return &original{}
}

func (original) ToReport(goID, modulePath string, _ *proxy.Client) *Report {
	return &Report{
		ID: goID,
		Modules: []*Module{
			{
				Module: modulePath,
			},
		},
		SourceMeta: &SourceMeta{
			ID: sourceGoTeam,
		},
	}
}

func (original) SourceID() string {
	return sourceGoTeam
}
