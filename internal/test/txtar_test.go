// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
)

func TestWriteTxtar(t *testing.T) {
	tmp := t.TempDir()

	filename := filepath.Join(tmp, "example", "file.txtar")
	files := []txtar.File{
		{
			Name: "a.txt",
			Data: []byte("abcdefg\n"),
		},
		{
			Name: "b.txt",
			Data: []byte("hijklmnop\n"),
		},
	}
	comment := "Context about this archive"

	if err := WriteTxtar(filename, files, comment); err != nil {
		t.Fatal(err)
	}

	got, err := txtar.ParseFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	want := &txtar.Archive{
		Comment: []byte(addBoilerplate(currentYear(), comment)),
		Files:   files,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
