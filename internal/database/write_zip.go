// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// WriteZip writes the database to filename as a zip file.
func (db *Database) WriteZip(filename string) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for endpoint, v := range map[string]any{dbEndpoint: db.DB, modulesEndpoint: db.Modules, vulnsEndpoint: db.Vulns} {
		if err := writeZip(zw, filepath.Join(indexDir, endpoint), v); err != nil {
			return err
		}
	}

	for _, entry := range db.Entries {
		if err := writeZip(zw, filepath.Join(idDir, entry.ID+".json"), entry); err != nil {
			return err
		}
	}

	return nil
}

// Unzip unzips the zip file in src and writes it to the directory dst.
func Unzip(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, f := range zr.File {
		fpath := filepath.Join(dst, f.Name)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		src, err := f.Open()
		if err != nil {
			return err
		}
		defer src.Close()

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		dst, err := os.Create(fpath)
		if err != nil {
			return err
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			return err
		}
	}
	return nil
}

func writeZip(zw *zip.Writer, filename string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	w, err := zw.Create(filename)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}

	return nil
}
