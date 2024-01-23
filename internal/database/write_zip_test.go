// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"path/filepath"
	"testing"
)

func TestWriteZip(t *testing.T) {
	tmp, want, got := t.TempDir(), t.TempDir(), t.TempDir()
	if err := txtarToDir(validTxtar, want, false); err != nil {
		t.Fatal(err)
	}

	zipped := filepath.Join(tmp, "all.zip")
	if err := valid.WriteZip(zipped); err != nil {
		t.Fatal("WriteZip:", err)
	}

	if err := Unzip(zipped, got); err != nil {
		t.Fatal("Unzip:", err)
	}

	if err := cmpDirHashes(want, got); err != nil {
		t.Error(err)
	}
}
