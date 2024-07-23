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
	ToReport(pxc *proxy.Client, modulePath string) *Report
}

func New(src Source, pc *proxy.Client, opts ...NewOption) *Report {
	cfg := newCfg(opts)

	r := src.ToReport(pc, cfg.ModulePath)
	r.ID = cfg.GoID
	r.AddAliases(cfg.Aliases)

	r.SourceMeta = &SourceMeta{
		ID: src.SourceID(),
	}
	r.SourceMeta.Created = &cfg.Created
	r.ReviewStatus = cfg.ReviewStatus
	r.Unexcluded = cfg.Unexcluded

	if r.hasExternalSource() {
		r.addSourceAdvisory()
	}

	r.Fix(pc)

	if r.ReviewStatus == Unreviewed {
		r.Description = ""
		// Package-level data is often wrong/incomplete, which could lead
		// to false negatives, so remove it for unreviewed reports.
		// TODO(tatianabradley): instead of removing all package-level data,
		// consider doing a surface-level check such as making sure packages are
		// known to pkgsite.
		r.removePackages(pc)
	}

	return r
}

func (r *Report) removePackages(pc *proxy.Client) {
	removed := false
	for _, m := range r.Modules {
		if !m.IsFirstParty() && len(m.Packages) != 0 {
			m.Packages = nil
			removed = true
		}
	}
	// If any packages were removed, we may need to merge some modules.
	if removed {
		_ = r.FixModules(pc)
	}
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

func WithReviewStatus(status ReviewStatus) NewOption {
	return func(h *cfg) {
		h.ReviewStatus = status
	}
}

func WithUnexcluded(reason ExcludedReason) NewOption {
	return func(h *cfg) {
		h.Unexcluded = reason
	}
}

type cfg struct {
	ModulePath   string
	Aliases      []string
	Created      time.Time
	GoID         string
	ReviewStatus ReviewStatus
	Unexcluded   ExcludedReason
}

const PendingID = "GO-ID-PENDING"

func newCfg(opts []NewOption) *cfg {
	h := &cfg{
		GoID:         PendingID,
		Created:      time.Now(),
		ReviewStatus: Unreviewed,
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
type original struct {
	cveID string // the Go-CNA-assigned CVE for this report, if applicable
}

var _ Source = &original{}

func Original() Source {
	return &original{}
}

func OriginalCVE(cveID string) Source {
	return &original{cveID: cveID}
}

func (o *original) ToReport(_ *proxy.Client, modulePath string) *Report {
	var cveMeta *CVEMeta
	if o.cveID != "" {
		cveMeta = &CVEMeta{ID: o.cveID}
	}
	return &Report{
		Modules: []*Module{
			{
				Module: modulePath,
			},
		},
		CVEMetadata: cveMeta,
	}
}

func (original) SourceID() string {
	return sourceGoTeam
}
