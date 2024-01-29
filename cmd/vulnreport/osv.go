// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"time"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

func osvCmd(_ context.Context, filename string, pc *proxy.Client) (err error) {
	defer derrors.Wrap(&err, "osv(%q)", filename)

	r, err := report.ReadAndLint(filename, pc)
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
