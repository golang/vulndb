// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/cve5"
)

type fileWriter struct{ wfs }

func (f *fileWriter) setup(_ context.Context, env environment) error {
	f.wfs = env.WFS()
	return nil
}

func (f *fileWriter) write(r *yamlReport) error {
	w := bytes.NewBuffer(make([]byte, 0))
	if err := r.Encode(w); err != nil {
		return err
	}
	if err := f.WriteFile(r.Filename, w.Bytes()); err != nil {
		return err
	}
	return ok(r.Filename)
}

func (f *fileWriter) writeOSV(r *yamlReport) error {
	if r.IsExcluded() {
		return nil
	}

	entry, err := r.ToOSV(time.Time{})
	if err != nil {
		return err
	}

	return writeJSON(f, r.OSVFilename(), entry)
}

func (f *fileWriter) writeCVE(r *yamlReport) error {
	if r.CVEMetadata == nil {
		return nil
	}

	cve, err := cve5.FromReport(r.Report)
	if err != nil {
		return err
	}
	return writeJSON(f, r.CVEFilename(), cve)
}

func (f *fileWriter) writeDerived(r *yamlReport) error {
	if err := f.writeOSV(r); err != nil {
		return err
	}
	return f.writeCVE(r)
}

func writeJSON(wfs wfs, fname string, v any) error {
	j, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := wfs.WriteFile(fname, j); err != nil {
		return err
	}
	return ok(fname)
}

func ok(fname string) error {
	log.Out(filepath.ToSlash(fname))
	return nil
}

// a simple representation of a writeable file system
type wfs interface {
	WriteFile(string, []byte) error
}

type defaultWFS struct{}

func (defaultWFS) WriteFile(filename string, b []byte) error {
	return os.WriteFile(filename, b, 0644)
}
