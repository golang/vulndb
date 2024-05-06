// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/report"
)

type cveCmd struct{ filenameParser }

func (cveCmd) name() string { return "cve" }

func (cveCmd) usage() (string, string) {
	const desc = "creates and saves CVE 5.0 record from the provided YAML reports"
	return filenameArgs, desc
}

func (c *cveCmd) setup(ctx context.Context) error {
	return nil
}

func (c *cveCmd) close() error { return nil }

func (c *cveCmd) run(ctx context.Context, filename string) (err error) {
	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if r.CVEMetadata != nil {
		if err := writeCVE(r); err != nil {
			return err
		}
		log.Out(r.CVEFilename())
	}
	return nil
}

// writeCVE converts a report to JSON CVE5 record and writes it to
// data/cve/v5.
func writeCVE(r *report.Report) error {
	cve, err := cve5.FromReport(r)
	if err != nil {
		return err
	}
	return database.WriteJSON(r.CVEFilename(), cve, true)
}
