// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"time"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/report"
)

func writeReport(r *report.Report) error {
	fname, err := r.YAMLFilename()
	if err != nil {
		return err
	}
	if err := r.Write(fname); err != nil {
		return err
	}
	return ok(fname)
}

func writeOSV(r *report.Report) error {
	if r.IsExcluded() {
		return nil
	}

	return writeJSON(r.OSVFilename(), r.ToOSV(time.Time{}))
}

func writeCVE(r *report.Report) error {
	if r.CVEMetadata == nil {
		return nil
	}

	cve, err := cve5.FromReport(r)
	if err != nil {
		return err
	}
	return writeJSON(r.CVEFilename(), cve)
}

func writeDerived(r *report.Report) error {
	if err := writeOSV(r); err != nil {
		return err
	}
	return writeCVE(r)
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

func remove(fname string) {
	if err := os.Remove(fname); err != nil {
		log.Errf("could not remove %s: %v", fname, err)
	}
	log.Infof("removed %s", fname)
}
