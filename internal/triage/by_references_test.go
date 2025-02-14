// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17

package triage

import (
	"context"
	"flag"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/cve5"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/stdlib"
)

var usePkgsite = flag.Bool("pkgsite", false, "use pkg.go.dev for tests")

func TestRefersToGoModuleV4CVE(t *testing.T) {
	ctx := context.Background()
	pc, err := pkgsite.TestClient(t, *usePkgsite)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		desc string
		in   Vuln
		want *Result
	}{
		{
			name: "unknown_std",
			desc: "repo path is unknown Go standard library",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
					},
				},
			},
			want: &Result{
				ModulePath: stdlib.ModulePath,
			},
		},
		{
			name: "std",
			desc: "pkg.go.dev URL is Go standard library package",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://pkg.go.dev/net/http"},
					},
				},
			},
			want: &Result{
				ModulePath:  stdlib.ModulePath,
				PackagePath: "net/http",
			},
		},
		{
			name: "repo_golang_org",
			desc: "repo path is is valid golang.org module path",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
						{URL: "https://golang.org/x/mod"},
					},
				},
			},
			want: &Result{
				ModulePath: "golang.org/x/mod",
			},
		},
		{
			name: "pkg_golang_org",
			desc: "pkg.go.dev URL is is valid golang.org module path",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://pkg.go.dev/golang.org/x/mod"},
					},
				},
			},
			want: &Result{
				ModulePath: "golang.org/x/mod",
			},
		},
		{
			name: "golang_org_pkg",
			desc: "contains golang.org/pkg URL",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://golang.org/pkg/net/http"},
					},
				},
			},
			want: &Result{
				ModulePath:  stdlib.ModulePath,
				PackagePath: "net/http",
			},
		},
		{
			name: "github_only",
			desc: "contains github.com but not on pkg.go.dev",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://github.com/something/something/404"},
					},
				},
			},
			want: nil,
		},
		{
			name: "long_path",
			desc: "contains longer module path",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://golang.org/x/exp/event"},
					},
				},
			},
			want: &Result{
				ModulePath: "golang.org/x/exp/event",
			},
		},
		{
			name: "not_module",
			desc: "repo path is not a module",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://bitbucket.org/foo/bar"},
					},
				},
			},
			want: nil,
		},
		{
			name: "golang_snyk",
			desc: "contains snyk.io URL containing GOLANG",
			in: &cve4.CVE{
				References: cve4.References{
					Data: []cve4.Reference{
						{URL: "https://snyk.io/vuln/SNYK-GOLANG-12345"},
					},
				},
			},
			want: &Result{
				ModulePath: unknownPath,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := RefersToGoModule(ctx, test.in, pc)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got,
				cmp.AllowUnexported(Result{}),
				cmpopts.IgnoreFields(Result{}, "Reason")); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestRefersToGoModuleV5CVE(t *testing.T) {
	ctx := context.Background()
	pc, err := pkgsite.TestClient(t, *usePkgsite)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		desc string
		in   Vuln
		want *Result
	}{
		{
			name: "unknown_std",
			desc: "repo path is unknown Go standard library",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
						},
					},
				},
			},
			want: &Result{
				ModulePath: stdlib.ModulePath,
			},
		},
		{
			name: "std",
			desc: "pkg.go.dev URL is Go standard library package",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://pkg.go.dev/net/http"},
						},
					},
				},
			},
			want: &Result{
				ModulePath:  stdlib.ModulePath,
				PackagePath: "net/http",
			},
		},
		{
			name: "repo_golang_org",
			desc: "repo path is is valid golang.org module path",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
							{URL: "https://golang.org/x/mod"},
						},
					},
				},
			},
			want: &Result{
				ModulePath: "golang.org/x/mod",
			},
		},
		{
			name: "pkg_golang_org",
			desc: "pkg.go.dev URL is is valid golang.org module path",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://pkg.go.dev/golang.org/x/mod"},
						},
					},
				},
			},
			want: &Result{
				ModulePath: "golang.org/x/mod",
			},
		},
		{
			name: "golang_org_pkg",
			desc: "contains golang.org/pkg URL",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://golang.org/pkg/net/http"},
						},
					},
				},
			},
			want: &Result{
				ModulePath:  stdlib.ModulePath,
				PackagePath: "net/http",
			},
		},
		{
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://github.com/something/something/404"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "long_path",
			desc: "contains longer module path",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://golang.org/x/exp/event"},
						},
					},
				},
			},
			want: &Result{
				ModulePath: "golang.org/x/exp/event",
			},
		},
		{
			name: "not_module",
			desc: "repo path is not a module",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://bitbucket.org/foo/bar"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "golang_snyk",
			desc: "contains snyk.io URL containing GOLANG",
			in: &cve5.CVERecord{
				Containers: cve5.Containers{
					CNAContainer: cve5.CNAPublishedContainer{
						References: []cve5.Reference{
							{URL: "https://snyk.io/vuln/SNYK-GOLANG-12345"},
						},
					},
				},
			},
			want: &Result{
				ModulePath: unknownPath,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := RefersToGoModule(ctx, test.in, pc)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got,
				cmp.AllowUnexported(Result{}),
				cmpopts.IgnoreFields(Result{}, "Reason")); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestAliasGHSAs(t *testing.T) {
	cve := &cve4.CVE{
		References: cve4.References{
			Data: []cve4.Reference{
				{URL: "https://github.com/hello/security/advisories/GHSA-xxxx-yyyy-0000"},
				{URL: "some/url"},
			},
		},
	}
	want := "GHSA-xxxx-yyyy-0000"
	if got := AliasGHSAs(cve); got[0] != want {
		t.Errorf("AliasGHSAs: got %s, want %s", got, want)
	}
}
