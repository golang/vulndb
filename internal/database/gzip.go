// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"os"
)

// writeGzipped compresses the data in data and writes it to
// to filename, creating the file if needed.
func writeGzipped(filename string, data []byte) error {
	var b bytes.Buffer
	w, err := gzip.NewWriterLevel(&b, 9)
	if err != nil {
		return err
	}
	defer w.Close()

	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(filename, b.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}

// readGzipped returns the uncompressed bytes of gzipped file filename.
func readGzipped(filename string) ([]byte, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(b)
	r, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return ioutil.ReadAll(r)
}
