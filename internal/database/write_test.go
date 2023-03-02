// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

func TestWrite(t *testing.T) {
	want := t.TempDir()
	gzip := true
	if err := txtarToDir(validTxtar, want, gzip); err != nil {
		t.Fatal(err)
	}

	got := t.TempDir()
	if err := valid.Write(got); err != nil {
		t.Fatal(err)
	}

	if err := cmpDirHashes(want, got); err != nil {
		t.Error(err)
	}
}

func TestLoadWrite(t *testing.T) {
	// Check that Load and Write are inverses.
	want := t.TempDir()
	gzip := true
	if err := txtarToDir(validTxtar, want, gzip); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(want)
	if err != nil {
		t.Fatal(err)
	}

	got := t.TempDir()
	if err := loaded.Write(got); err != nil {
		t.Fatal(err)
	}

	if err := cmpDirHashes(want, got); err != nil {
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
