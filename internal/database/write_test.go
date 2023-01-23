// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/mod/sumdb/dirhash"
)

func TestWrite(t *testing.T) {
	tempDir := t.TempDir()

	if err := valid.Write(tempDir, true); err != nil {
		t.Fatal(err)
	}

	if err := cmpDirHashes(tempDir, validDir); err != nil {
		t.Error(err)
	}
}

// cmpDirHashes compares the contents of two directories by comparing
// their hashes.
func cmpDirHashes(d1, d2 string) error {
	h1, err := dirhash.HashDir(d1, "", dirhash.DefaultHash)
	if err != nil {
		return fmt.Errorf("could not hash dir %q: %v", d1, err)
	}
	h2, err := dirhash.HashDir(d2, "", dirhash.DefaultHash)
	if err != nil {
		return fmt.Errorf("could not hash dir %q: %v", d2, err)
	}
	if h1 != h2 {
		return fmt.Errorf("hashes do not match:\n%s: %s\n%s: %s", d1, h1, d2, h2)
	}
	return nil
}

// Check that Write and Load are inverses.
func TestWriteLoad(t *testing.T) {
	tempDir := t.TempDir()

	written := valid
	if err := written.Write(tempDir, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(written, loaded); diff != "" {
		t.Errorf("unexpected diff (written- loaded+):\n %s", diff)
	}
}
