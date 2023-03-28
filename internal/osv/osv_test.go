// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osv_test

import (
	"testing"

	"golang.org/x/vulndb/internal/test"
)

func TestImports(t *testing.T) {
	// package osv only allows non stdlib imports.
	//
	// This is intended to make it easy for anyone to copy and paste the
	// JSON structs if needed.
	test.VerifyImports(t)
}
