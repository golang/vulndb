// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stdlib contains functionality relevant to the Go Standard Library.
package stdlib

import (
	"strings"

	"golang.org/x/mod/module"
)

const (
	// ModulePath is the name of the Go standard library module.
	ModulePath = "std"
	// ToolchainModulePath is the name of the module containing Go
	// toolchain binaries.
	ToolchainModulePath = "cmd"
)

// Contains reports whether the given import path could be part of the Go
// standard library, by reporting whether the first component lacks a '.'.
func Contains(path string) bool {
	if err := module.CheckImportPath(path); err != nil {
		return false
	}
	if i := strings.IndexByte(path, '/'); i != -1 {
		path = path[:i]
	}
	return !strings.Contains(path, ".")
}

func IsStdModule(path string) bool {
	return path == ModulePath
}

func IsCmdModule(path string) bool {
	return path == ToolchainModulePath
}

func IsXModule(path string) bool {
	return strings.HasPrefix(path, "golang.org/x/")
}
