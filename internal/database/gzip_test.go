// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"path/filepath"
	"testing"
)

func TestWriteReadGzipped(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "test.json.gz")

	want := []byte(`{"test":"Hello world!"}`)
	if err := writeGzipped(filename, want); err != nil {
		t.Fatal(err)
	}

	got, err := readGzipped(filename)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(want) {
		t.Errorf("readGzipped: got %s, want %s", got, want)
	}
}
