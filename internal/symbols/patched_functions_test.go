// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestModuleRoots(t *testing.T) {
	want := map[string]string{
		"golang.org/module":       "testdata/module",
		"golang.org/nestedmodule": "testdata/module/submodule",
	}
	got, err := moduleRoots("testdata/module")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-got, want+):\n%s", diff)
	}
}
