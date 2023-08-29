// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCanonicalModulePath(t *testing.T) {
	tcs := []struct {
		name     string
		path     string
		version  string
		response string // hard-coded response
		want     string
	}{
		{
			name:     "non-canonical",
			path:     "github.com/golang/vulndb",
			version:  "v0.0.0-20230522180520-0cbf4ffdb4e7",
			response: "module golang.org/x/vulndb",
			want:     "golang.org/x/vulndb",
		},
		{
			name:     "canonical",
			path:     "golang.org/x/vulndb",
			version:  "v0.0.0-20230522180520-0cbf4ffdb4e7",
			response: "module golang.org/x/vulndb",
			want:     "golang.org/x/vulndb",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := fmt.Sprintf("%s/@v/%s.mod", tc.path, tc.version)
			c, cleanup := fakeClient(map[string]*response{
				endpoint: {
					Body:       tc.response,
					StatusCode: http.StatusOK,
				}})
			t.Cleanup(cleanup)
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
		name     string
		path     string
		version  string
		response string // hard-coded response
		want     string
	}{
		{
			name:     "already canonical",
			path:     "golang.org/x/vulndb",
			version:  "v0.0.0-20230522180520-0cbf4ffdb4e7",
			response: `{"Version":"v0.0.0-20230522180520-0cbf4ffdb4e7"}`,
			want:     "0.0.0-20230522180520-0cbf4ffdb4e7",
		},
		{
			name:     "commit hash",
			path:     "golang.org/x/vulndb",
			version:  "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
			response: `{"Version":"v0.0.0-20230522180520-0cbf4ffdb4e7"}`,
			want:     "0.0.0-20230522180520-0cbf4ffdb4e7",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := fmt.Sprintf("%s/@v/%s.info", tc.path, tc.version)
			c, cleanup := fakeClient(map[string]*response{
				endpoint: {
					Body:       tc.response,
					StatusCode: http.StatusOK,
				}})
			t.Cleanup(cleanup)
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

func TestVersions(t *testing.T) {
	tcs := []struct {
		name     string
		path     string
		response string // hard-coded response
		want     []string
	}{
		{
			name:     "no tagged versions",
			path:     "golang.org/x/vulndb",
			response: "",
			want:     nil,
		},
		{
			name: "unsorted -> sorted",
			path: "golang.org/x/tools",
			response: `
v0.1.4
v0.9.3
v0.7.0
`,
			want: []string{"0.1.4", "0.7.0", "0.9.3"},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := fmt.Sprintf("%s/@v/list", tc.path)
			c, cleanup := fakeClient(map[string]*response{
				endpoint: {
					Body:       tc.response,
					StatusCode: http.StatusOK,
				}})
			t.Cleanup(cleanup)
			got, err := c.Versions(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Versions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLatest(t *testing.T) {
	tcs := []struct {
		path     string
		response string // hard-coded response
		want     string
	}{
		{
			path:     "golang.org/x/vulndb",
			response: `{"Version":"v0.0.0-20230522180520-0cbf4ffdb4e7"}`,
			want:     "0.0.0-20230522180520-0cbf4ffdb4e7",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.path, func(t *testing.T) {
			endpoint := fmt.Sprintf("%s/@latest", tc.path)
			c, cleanup := fakeClient(map[string]*response{
				endpoint: {
					Body:       tc.response,
					StatusCode: http.StatusOK,
				}})
			t.Cleanup(cleanup)
			got, err := c.Latest(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Latest() = %v, want %v", got, tc.want)
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
			c, cleanup := fakeClient(map[string]*response{
				endpoint: {
					Body:       tc.want,
					StatusCode: http.StatusOK,
				},
			})
			t.Cleanup(cleanup)
			if got := c.FindModule(tc.path); got != tc.want {
				t.Errorf("FindModule() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCacheAndErrors(t *testing.T) {
	okEndpoint, notFoundEndpoint := "endpoint", "not/found"
	okResponse := "response"
	responses := map[string]*response{
		okEndpoint: {
			Body:       okResponse,
			StatusCode: http.StatusOK,
		},
		notFoundEndpoint: {
			Body:       "",
			StatusCode: http.StatusNotFound,
		},
	}
	c, cleanup := fakeClient(responses)
	t.Cleanup(cleanup)

	wantHits := 3
	for i := 0; i < wantHits+1; i++ {
		b, err := c.lookup(okEndpoint)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(b), okResponse; got != want {
			t.Errorf("lookup(%q) = %s, want %s", okEndpoint, got, want)
		}
	}
	if c.cache.hits != wantHits {
		t.Errorf("cache hits = %d, want %d", c.cache.hits, wantHits)
	}

	if _, err := c.lookup(notFoundEndpoint); err == nil {
		t.Errorf("lookup(%q) succeeded, want error", notFoundEndpoint)
	}

	want, got := responses, c.responses()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Responses() unexpected diff (want-, got+):\n%s", diff)
	}
}
