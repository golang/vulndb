// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"time"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/database"
)

func (r *yamlReport) write() error {
	if err := r.Write(r.filename); err != nil {
		return err
	}
	return ok(r.filename)
}

func (r *yamlReport) writeOSV() error {
	if r.IsExcluded() {
		return nil
	}

	return writeJSON(r.OSVFilename(), r.ToOSV(time.Time{}))
}

func (r *yamlReport) writeCVE() error {
	if r.CVEMetadata == nil {
		return nil
	}

	cve, err := cve5.FromReport(r.Report)
	if err != nil {
		return err
	}
	return writeJSON(r.CVEFilename(), cve)
}

func (r *yamlReport) writeDerived() error {
	if err := r.writeOSV(); err != nil {
		return err
	}
	return r.writeCVE()
}

func writeJSON(fname string, v any) error {
	if err := database.WriteJSON(fname, v, true); err != nil {
		return err
	}
	return ok(fname)
}

func ok(fname string) error {
	log.Out(fname)
	return nil
}
