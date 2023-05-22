// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"runtime"
	"testing"
)

func TestCanonicalModulePath(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	tcs := []struct {
		name    string
		path    string
		version string
		want    string
	}{
		{
			name:    "non-canonical",
			path:    "github.com/golang/vulndb",
			version: "v0.0.0-20230522180520-0cbf4ffdb4e7",
			want:    "golang.org/x/vulndb",
		},
		{
			name:    "canonical",
			path:    "golang.org/x/vulndb",
			version: "v0.0.0-20230522180520-0cbf4ffdb4e7",
			want:    "golang.org/x/vulndb",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalModulePath(tc.path, tc.version)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("CanonicalModulePath() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanonicalModuleVersion(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	tcs := []struct {
		name    string
		path    string
		version string
		want    string
	}{
		{
			name:    "already canonical",
			path:    "golang.org/x/vulndb",
			version: "v0.0.0-20230522180520-0cbf4ffdb4e7",
			want:    "v0.0.0-20230522180520-0cbf4ffdb4e7",
		},
		{
			name:    "commit hash",
			path:    "golang.org/x/vulndb",
			version: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
			want:    "v0.0.0-20230522180520-0cbf4ffdb4e7",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalModuleVersion(tc.path, tc.version)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("CanonicalModuleVersion() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFindModule(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	tcs := []struct {
		name string
		path string
		want string
	}{
		{
			name: "module is a prefix of path",
			path: "k8s.io/kubernetes/staging/src/k8s.io/apiserver/pkg/server",
			want: "k8s.io/kubernetes/staging/src/k8s.io/apiserver",
		},
		{
			name: "path is a module",
			path: "k8s.io/kubernetes/staging/src/k8s.io/apiserver",
			want: "k8s.io/kubernetes/staging/src/k8s.io/apiserver",
		},
		{
			name: "stdlib package",
			path: "net/http",
			want: "net/http",
		},
		{
			name: "no module (3p)",
			path: "example.co.io/module/package/src/versions/v8",
			want: "",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := FindModule(tc.path); got != tc.want {
				t.Errorf("FindModule() = %v, want %v", got, tc.want)
			}
		})
	}
}
