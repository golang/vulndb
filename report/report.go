// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import "time"

type VersionRange struct {
	Introduced string
	Fixed      string
}

type Report struct {
	Module  string
	Package string
	// TODO: could also be GoToolchain, but we might want
	// this for other things?
	//
	// could we also automate this by just looking for
	// things prefixed with cmd/go?
	DoNotExport bool `json:"do_not_export"`
	// TODO: how does this interact with Versions etc?
	Stdlib bool `json:"stdlib"`
	// TODO: the most common usage of additional package should
	// really be replaced with 'aliases', we'll still need
	// additional packages for some cases, but it's too heavy
	// for most
	AdditionalPackages []struct {
		Module   string
		Package  string
		Symbols  []string
		Versions []VersionRange
	} `toml:"additional_packages"`
	Versions     []VersionRange
	Description  string
	Published    time.Time
	LastModified *time.Time `toml:"last_modified"`
	Withdrawn    *time.Time
	CVE          string
	Credit       string
	Symbols      []string
	OS           []string
	Arch         []string
	Links        struct {
		PR      string
		Commit  string
		Context []string
	}
	CVEMetadata *struct {
		ID          string
		CWE         string
		Description string
	} `toml:"cve_metadata"`
}
