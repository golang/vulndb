// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"errors"
	"flag"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")

func TestCanonicalModulePath(t *testing.T) {
	c, err := NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
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
			version: "0.0.0-20230522180520-0cbf4ffdb4e7",
			want:    "golang.org/x/vulndb",
		},
		{
			name:    "canonical",
			path:    "golang.org/x/vulndb",
			version: "0.0.0-20230522180520-0cbf4ffdb4e7",
			want:    "golang.org/x/vulndb",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
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
	c, err := NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name    string
		path    string
		version string
		want    string
	}{
		{
			name:    "tagged version already canonical",
			path:    "golang.org/x/vuln",
			version: "0.1.0",
			want:    "0.1.0",
		},
		{
			name:    "pseudo-version already canonical",
			path:    "golang.org/x/vulndb",
			version: "0.0.0-20230522180520-0cbf4ffdb4e7",
			want:    "0.0.0-20230522180520-0cbf4ffdb4e7",
		},
		{
			name:    "commit hash",
			path:    "golang.org/x/vulndb",
			version: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
			want:    "0.0.0-20230522180520-0cbf4ffdb4e7",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
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
	c, err := NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "no tagged versions",
			path: "golang.org/x/vulndb",
			want: nil,
		},
		{
			name: "tagged versions",
			path: "golang.org/x/vuln",
			want: []string{
				"0.1.0",
				"0.2.0",
				"1.0.0",
				"1.0.1",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
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
	c, err := NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		path string
		want string
	}{
		{
			path: "golang.org/x/vulndb",
			want: "0.0.0-20230911193511-c7cbbd05f085",
		},
		{
			path: "golang.org/x/vuln",
			want: "1.0.1",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.path, func(t *testing.T) {
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
	c, err := NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name    string
		path    string
		want    string
		wantErr error
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
			name:    "no module",
			path:    "example.co.io/module/package/src/versions/v8",
			wantErr: errNoModuleFound,
		},
		{
			name: "module needs to be escaped",
			path: "github.com/RobotsAndPencils/go-saml/util",
			want: "github.com/RobotsAndPencils/go-saml",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.FindModule(tc.path)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("FindModule() error = %v, want err containing %v", err, tc.wantErr)
			} else if got != tc.want {
				t.Errorf("FindModule() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestModuleExists(t *testing.T) {
	c, err := NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "exists",
			path: "k8s.io/kubernetes",
			want: true,
		},
		{
			name: "exists (needs escape)",
			path: "github.com/RobotsAndPencils/go-saml",
			want: true,
		},
		{
			name: "does not exist",
			path: "example.com/not/a/module",
			want: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ModuleExists(tc.path)
			if got != tc.want {
				t.Errorf("ModuleExists() = %v, want %v", got, tc.want)
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
