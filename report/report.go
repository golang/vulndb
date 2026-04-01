// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package report exports the VulnDB
// Report shape for internal security
// release tooling to consume.
//
// Despite this type being exported, it
// should be considered an implementation
// detail meant for internal use by the
// Go Security Team; it is not subject to
// the Go 1 compatibility promise and may
// change at any time.
package report

import (
	"golang.org/x/vulndb/internal/osv"
	internal "golang.org/x/vulndb/internal/report"
)

type (
	Report              = internal.Report
	Module              = internal.Module
	Version             = internal.Version
	VersionType         = internal.VersionType
	Versions            = internal.Versions
	VulnerableAtVersion = internal.VulnerableAtVersion
	Package             = internal.Package
	CVEMeta             = internal.CVEMeta
	Reference           = internal.Reference
	ReviewStatus        = internal.ReviewStatus
	SourceMeta          = internal.SourceMeta
	Summary             = internal.Summary
	Description         = internal.Description
)

type (
	Time          = osv.Time
	ReferenceType = osv.ReferenceType
)

const (
	VersionTypeIntroduced   = internal.VersionTypeIntroduced
	VersionTypeFixed        = internal.VersionTypeFixed
	VersionTypeVulnerableAt = internal.VersionTypeVulnerableAt
)

const (
	Reviewed    = internal.Reviewed
	Unreviewed  = internal.Unreviewed
	NeedsReview = internal.NeedsReview
)

const (
	ReferenceTypeAdvisory = osv.ReferenceTypeAdvisory
	ReferenceTypeArticle  = osv.ReferenceTypeArticle
	ReferenceTypeReport   = osv.ReferenceTypeReport
	ReferenceTypeFix      = osv.ReferenceTypeFix
	ReferenceTypePackage  = osv.ReferenceTypePackage
	ReferenceTypeEvidence = osv.ReferenceTypeEvidence
	ReferenceTypeWeb      = osv.ReferenceTypeWeb
)

func Introduced(v string) *Version   { return internal.Introduced(v) }
func Fixed(v string) *Version        { return internal.Fixed(v) }
func VulnerableAt(v string) *Version { return internal.VulnerableAt(v) }
