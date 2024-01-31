// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"time"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

type osvCmd struct {
	pc *proxy.Client

	filenameParser
}

func (osvCmd) name() string { return "osv" }

func (osvCmd) usage() (string, string) {
	const desc = "converts YAML reports to OSV JSON and writes to data/osv"
	return filenameArgs, desc
}

func (o *osvCmd) setup(ctx context.Context) error {
	o.pc = proxy.NewDefaultClient()
	return nil
}

func (o *osvCmd) close() error { return nil }

func (o *osvCmd) run(ctx context.Context, filename string) (err error) {
	r, err := report.ReadAndLint(filename, o.pc)
	if err != nil {
		return err
	}
	if !r.IsExcluded() {
		if err := writeOSV(r); err != nil {
			return err
		}
		log.Out(r.OSVFilename())
	}
	return nil
}

func writeOSV(r *report.Report) error {
	return database.WriteJSON(r.OSVFilename(), r.ToOSV(time.Time{}), true)
}
