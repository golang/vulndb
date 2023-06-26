// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func newTestClient(expectedEndpoint, mockResponse string) *Client {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet &&
			r.URL.Path == "/"+expectedEndpoint {
			_, _ = w.Write([]byte(mockResponse))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}
	s := httptest.NewServer(http.HandlerFunc(handler))
	return NewClient(s.Client(), s.URL)
}

func TestCanonicalModulePath(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skipf("wasm builder does not have network access")
	}
	tcs := []struct {
		name         string
		path         string
		version      string
		mockResponse string
		want         string
	}{
		{
			name:         "non-canonical",
			path:         "github.com/golang/vulndb",
			version:      "v0.0.0-20230522180520-0cbf4ffdb4e7",
			mockResponse: "module golang.org/x/vulndb",
			want:         "golang.org/x/vulndb",
		},
		{
			name:         "canonical",
			path:         "golang.org/x/vulndb",
			version:      "v0.0.0-20230522180520-0cbf4ffdb4e7",
			mockResponse: "module golang.org/x/vulndb",
			want:         "golang.org/x/vulndb",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := fmt.Sprintf("%s/@v/%s.mod", tc.path, tc.version)
			c := newTestClient(endpoint, tc.mockResponse)
			got, err := c.CanonicalModulePath(tc.path, tc.version)
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
	tcs := []struct {
		name         string
		path         string
		version      string
		mockResponse string
		want         string
	}{
		{
			name:         "already canonical",
			path:         "golang.org/x/vulndb",
			version:      "v0.0.0-20230522180520-0cbf4ffdb4e7",
			mockResponse: `{"Version":"v0.0.0-20230522180520-0cbf4ffdb4e7"}`,
			want:         "v0.0.0-20230522180520-0cbf4ffdb4e7",
		},
		{
			name:         "commit hash",
			path:         "golang.org/x/vulndb",
			version:      "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
			mockResponse: `{"Version":"v0.0.0-20230522180520-0cbf4ffdb4e7"}`,
			want:         "v0.0.0-20230522180520-0cbf4ffdb4e7",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := fmt.Sprintf("%s/@v/%s.info", tc.path, tc.version)
			c := newTestClient(endpoint, tc.mockResponse)
			got, err := c.CanonicalModuleVersion(tc.path, tc.version)
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
			endpoint := fmt.Sprintf("%s/@v/list", tc.want)
			c := newTestClient(endpoint, "")
			if got := c.FindModule(tc.path); got != tc.want {
				t.Errorf("FindModule() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCache(t *testing.T) {
	endpoint := "endpoint"
	want := "response"
	wantHits := 3
	c := newTestClient(endpoint, want)
	for i := 0; i < wantHits+1; i++ {
		b, err := c.lookup("endpoint")
		if err != nil {
			t.Fatal(err)
		}
		if got := string(b); got != want {
			t.Errorf("lookup() = %s, want %s", got, want)
		}
	}
	if c.cache.hits != wantHits {
		t.Errorf("cache hits = %d, want %d", c.cache.hits, wantHits)
	}
}
