// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"time"

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

const PendingID = "GO-ID-PENDING"

func newCfg(opts []NewOption) *cfg {
	h := &cfg{
		GoID: PendingID,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
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
