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
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/stdlib"
)

var usePkgsite = flag.Bool("pkgsite", false, "use pkg.go.dev for tests")

func TestTriageV4CVE(t *testing.T) {
	ctx := context.Background()
	url := GetPkgsiteURL(t, *usePkgsite)

	for _, test := range []struct {
		name string
		in   *cveschema.CVE
		want *TriageResult
	}{
		{
			"repo path is unknown Go standard library",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
					},
				},
			},
			&TriageResult{
				ModulePath: stdlib.ModulePath,
			},
		},
		{
			"pkg.go.dev URL is Go standard library package",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://pkg.go.dev/net/http"},
					},
				},
			},
			&TriageResult{
				ModulePath:  stdlib.ModulePath,
				PackagePath: "net/http",
			},
		},
		{
			"repo path is is valid golang.org module path",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://groups.google.com/forum/#!topic/golang-nuts/1234"},
						{URL: "https://golang.org/x/mod"},
					},
				},
			},
			&TriageResult{
				ModulePath: "golang.org/x/mod",
			},
		},
		{
			"pkg.go.dev URL is is valid golang.org module path",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://pkg.go.dev/golang.org/x/mod"},
					},
				},
			},
			&TriageResult{
				ModulePath: "golang.org/x/mod",
			},
		},
		{
			"contains golang.org/pkg URL",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://golang.org/pkg/net/http"},
					},
				},
			},
			&TriageResult{
				ModulePath:  stdlib.ModulePath,
				PackagePath: "net/http",
			},
		},
		{
			"contains github.com but not on pkg.go.dev",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://github.com/something/something/404"},
					},
				},
			},
			nil,
		},
		{
			"contains longer module path",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://golang.org/x/exp/event"},
					},
				},
			},
			&TriageResult{
				ModulePath: "golang.org/x/exp/event",
			},
		},
		{
			"repo path is not a module",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://bitbucket.org/foo/bar"},
					},
				},
			},
			nil,
		},
		{
			"contains snyk.io URL containing GOLANG",
			&cveschema.CVE{
				References: cveschema.References{
					Data: []cveschema.Reference{
						{URL: "https://snyk.io/vuln/SNYK-GOLANG-12345"},
					},
				},
			},
			&TriageResult{
				ModulePath: unknownPath,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.in.DataVersion = "4.0"
			got, err := TriageCVE(ctx, test.in, url)
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

func TestKnownToPkgsite(t *testing.T) {
	ctx := context.Background()

	const validModule = "golang.org/x/mod"
	url := GetPkgsiteURL(t, *usePkgsite)

	for _, test := range []struct {
		in   string
		want bool
	}{
		{validModule, true},
		{"github.com/something/something", false},
	} {
		t.Run(test.in, func(t *testing.T) {
			got, err := knownToPkgsite(ctx, url, test.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("%s: got %t, want %t", test.in, got, test.want)
			}
		})
	}
}

func TestGetAliasGHSAs(t *testing.T) {
	cve := &cveschema.CVE{
		References: cveschema.References{
			Data: []cveschema.Reference{
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
