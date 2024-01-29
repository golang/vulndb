// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/report"
)

func cveCmd(_ context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "cve(%q)", filename)
	r, err := report.Read(filename)
	if err != nil {
		return err
	}
	if r.CVEMetadata != nil {
		if err := writeCVE(r); err != nil {
			return err
		}
		outlog.Println(r.CVEFilename())
	}
	return nil
}

// writeCVE converts a report to JSON CVE5 record and writes it to
// data/cve/v5.
func writeCVE(r *report.Report) error {
	cve, err := r.ToCVE5()
	if err != nil {
		return err
	}
	return database.WriteJSON(r.CVEFilename(), cve, true)
}
