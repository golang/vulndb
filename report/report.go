// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import "time"

type VersionRange struct {
	Introduced string `yaml:",omitempty"`
	Fixed      string `yaml:",omitempty"`
}

type Additional struct {
	Module   string         `yaml:",omitempty"`
	Package  string         `yaml:",omitempty"`
	Symbols  []string       `yaml:",omitempty"`
	Versions []VersionRange `yaml:",omitempty"`
}

type Links struct {
	PR      string   `yaml:",omitempty"`
	Commit  string   `yaml:",omitempty"`
	Context []string `yaml:",omitempty"`
}

type CVEMeta struct {
	ID          string `yaml:",omitempty"`
	CWE         string `yaml:",omitempty"`
	Description string `yaml:",omitempty"`
}

type Report struct {
	Module  string `yaml:",omitempty"`
	Package string `yaml:",omitempty"`
	// TODO: could also be GoToolchain, but we might want
	// this for other things?
	//
	// could we also automate this by just looking for
	// things prefixed with cmd/go?
	DoNotExport bool `yaml:"do_not_export,omitempty"`
	// TODO: how does this interact with Versions etc?
	Stdlib bool `yaml:",omitempty"`
	// TODO: the most common usage of additional package should
	// really be replaced with 'aliases', we'll still need
	// additional packages for some cases, but it's too heavy
	// for most
	AdditionalPackages []Additional   `yaml:"additional_packages,omitempty"`
	Versions           []VersionRange `yaml:",omitempty"`
	Description        string         `yaml:",omitempty"`
	Published          time.Time      `yaml:",omitempty"`
	LastModified       *time.Time     `yaml:"last_modified,omitempty"`
	Withdrawn          *time.Time     `yaml:",omitempty"`
	CVE                string         `yaml:",omitempty"`
	Credit             string         `yaml:",omitempty"`
	Symbols            []string       `yaml:",omitempty"`
	OS                 []string       `yaml:",omitempty"`
	Arch               []string       `yaml:",omitempty"`
	Links              Links          `yaml:",omitempty"`
	CVEMetadata        *CVEMeta       `yaml:"cve_metadata,omitempty"`
}
