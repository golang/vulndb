// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package cveutils

import (
	"context"
	"flag"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/stdlib"
)

var usePkgsite = flag.Bool("pkgsite", false, "use pkg.go.dev for tests")

func TestTriageV4CVE(t *testing.T) {
	ctx := context.Background()
	cf, err := pkgsite.CacheFile(t)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := pkgsite.TestClient(t, *usePkgsite, cf)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		desc string
		in   *cve4.CVE
		want *TriageResult
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
			want: &TriageResult{
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
			want: &TriageResult{
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
			want: &TriageResult{
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
			want: &TriageResult{
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
			want: &TriageResult{
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
			want: &TriageResult{
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
			want: &TriageResult{
				ModulePath: unknownPath,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.in.DataVersion = "4.0"
			got, err := TriageCVE(ctx, test.in, pc)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got,
				cmp.AllowUnexported(TriageResult{}),
				cmpopts.IgnoreFields(TriageResult{}, "Reason")); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestGetAliasGHSAs(t *testing.T) {
	cve := &cve4.CVE{
		References: cve4.References{
			Data: []cve4.Reference{
				{URL: "https://github.com/hello/security/advisories/GHSA-xxxx-yyyy-0000"},
				{URL: "some/url"},
			},
		},
	}
	want := "GHSA-xxxx-yyyy-0000"
	if got := GetAliasGHSAs(cve); got[0] != want {
		t.Errorf("getAliasGHSAs: got %s, want %s", got, want)
	}
}
