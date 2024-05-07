// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"time"

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
	ToReport(modulePath string) *Report
}

func New(src Source, pc *proxy.Client, opts ...NewOption) *Report {
	cfg := newCfg(opts)

	r := src.ToReport(cfg.ModulePath)
	r.ID = cfg.GoID
	r.AddAliases(cfg.Aliases)

	r.SourceMeta = &SourceMeta{
		ID: src.SourceID(),
	}
	if !cfg.Created.IsZero() {
		r.SourceMeta.Created = &cfg.Created
	}

	r.Fix(pc)
	return r
}

type Fetcher interface {
	Fetch(ctx context.Context, id string) (Source, error)
}

type NewOption func(*cfg)

func WithModulePath(path string) NewOption {
	return func(h *cfg) {
		h.ModulePath = path
	}
}

func WithAliases(aliases []string) NewOption {
	return func(h *cfg) {
		h.Aliases = aliases
	}
}

func WithCreated(created time.Time) NewOption {
	return func(h *cfg) {
		h.Created = created
	}
}

func WithGoID(id string) NewOption {
	return func(h *cfg) {
		h.GoID = id
	}
}

type cfg struct {
	ModulePath string
	Aliases    []string
	Created    time.Time
	GoID       string
}

const pendingID = "GO-ID-PENDING"

func newCfg(opts []NewOption) *cfg {
	h := &cfg{
		GoID: pendingID,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

type cve5 struct {
	*cveschema5.CVERecord
}

var _ Source = &cve5{}

func ToCVE5(c *cveschema5.CVERecord) Source {
	return &cve5{CVERecord: c}
}

func (c *cve5) ToReport(modulePath string) *Report {
	return cve5ToReport(c.CVERecord, modulePath)
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
type cve4 struct {
	*cveschema.CVE
}

var _ Source = &cve4{}

func ToCVE4(c *cveschema.CVE) Source {
	return &cve4{CVE: c}
}

func (c *cve4) ToReport(modulePath string) *Report {
	return cveToReport(c.CVE, modulePath)
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

func ToLegacyGHSA(g *ghsa.SecurityAdvisory) Source {
	return &legacyGHSA{
		SecurityAdvisory: g,
	}
}

func (g *legacyGHSA) ToReport(modulePath string) *Report {
	return ghsaToReport(g.SecurityAdvisory, modulePath)
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

func (original) ToReport(modulePath string) *Report {
	return &Report{
		Modules: []*Module{
			{
				Module: modulePath,
			},
		},
	}
}

func (original) SourceID() string {
	return sourceGoTeam
}
