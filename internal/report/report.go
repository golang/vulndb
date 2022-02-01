// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package report contains functionality for parsing and linting YAML reports
// in reports/.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/vulndb/internal/derrors"
	"gopkg.in/yaml.v3"
)

type VersionRange struct {
	Introduced string `yaml:"introduced,omitempty"`
	Fixed      string `yaml:"fixed,omitempty"`
}

type Additional struct {
	Module  string `yaml:",omitempty"`
	Package string `yaml:",omitempty"`
	// Symbols originally identified as vulnerable.
	Symbols []string `yaml:",omitempty"`
	// Additional vulnerable symbols, computed from Symbols via static analysis
	// or other technique.
	DerivedSymbols []string       `yaml:"derived_symbols,omitempty"`
	Versions       []VersionRange `yaml:",omitempty"`
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
	// TODO: the most common usage of additional package should
	// really be replaced with 'aliases', we'll still need
	// additional packages for some cases, but it's too heavy
	// for most
	AdditionalPackages []Additional   `yaml:"additional_packages,omitempty"`
	Versions           []VersionRange `yaml:"versions,omitempty"`

	// Description is the CVE description from an existing CVE. If we are
	// assigning a CVE ID ourselves, use CVEMetadata.Description instead.
	Description  string     `yaml:",omitempty"`
	Published    time.Time  `yaml:",omitempty"`
	LastModified *time.Time `yaml:"last_modified,omitempty"`
	Withdrawn    *time.Time `yaml:",omitempty"`

	// If we are assigning a CVE ID ourselves, use CVEMetdata.ID instead.
	// CVE are CVE IDs for existing CVEs, if there is more than one.
	// Use either CVE or CVEs, but not both.
	CVEs   []string `yaml:",omitempty"`
	Credit string   `yaml:",omitempty"`
	// Symbols originally identified as vulnerable.
	Symbols []string `yaml:",omitempty"`
	// Additional vulnerable symbols, computed from Symbols via static analysis
	// or other technique.
	DerivedSymbols []string `yaml:"derived_symbols,omitempty"`
	OS             []string `yaml:",omitempty"`
	Arch           []string `yaml:",omitempty"`
	Links          Links    `yaml:",omitempty"`

	// CVEMetdata is used to capture CVE information when we want to assign a
	// CVE ourselves. If a CVE already exists for an issue, use the CVE field
	// to fill in the ID string.
	CVEMetadata *CVEMeta `yaml:"cve_metadata,omitempty"`
}

// AllSymbols returns both original and derived symbols.
func (r *Report) AllSymbols() []string {
	return append(append([]string(nil), r.Symbols...), r.DerivedSymbols...)
}

// AllSymbols returns both original and derived symbols.
func (a *Additional) AllSymbols() []string {
	return append(append([]string(nil), a.Symbols...), a.DerivedSymbols...)
}

// Read reads a Report in YAML format from filename.
func Read(filename string) (_ *Report, err error) {
	defer derrors.Wrap(&err, "report.Read(%q)", filename)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	// Require that all fields in the file are in the struct.
	// This corresponds to v2's UnmarshalStrict.
	d.KnownFields(true)
	var r Report
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("yaml.Decode: %v", err)
	}
	return &r, nil
}

// Write writes r to filename in YAML format.
func (r *Report) Write(filename string) (err error) {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	err = r.encode(f)
	err2 := f.Close()
	if err == nil {
		err = err2
	}
	return err
}

// ToString encodes r to a YAML string.
func (r *Report) ToString() (string, error) {
	var b strings.Builder
	if err := r.encode(&b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (r *Report) encode(w io.Writer) error {
	e := yaml.NewEncoder(w)
	e.SetIndent(4)
	return e.Encode(r)
}
