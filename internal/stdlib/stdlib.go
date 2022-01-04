// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stdlib contains functionality relevant to the Go Standard Library.
package stdlib

import "strings"

const ModulePath = "std"

// Contains reports whether the given import path could be part of the Go
// standard library, by reporting whether the first component lacks a '.'.
func Contains(path string) bool {
	if i := strings.IndexByte(path, '/'); i != -1 {
		path = path[:i]
	}
	return !strings.Contains(path, ".")
}
