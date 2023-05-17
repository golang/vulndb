// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"runtime"
	"testing"
)

// TODO(https://go.dev/issues/60275): Add more unit tests.

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
