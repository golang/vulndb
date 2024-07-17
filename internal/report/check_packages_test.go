// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"errors"
	"flag"
	"testing"

	"golang.org/x/vulndb/internal/pkgsite"
)

var realPkgsite = flag.Bool("pkgsite", false, "use real pkgsite")

func TestCheckPackages(t *testing.T) {
	pkc, err := pkgsite.TestClient(t, *realPkgsite)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		r       *Report
		wantErr error
	}{
		{
			name: "ok: no packages",
			r: &Report{Modules: []*Module{
				{
					Module: "example.com/module",
				},
			}},
		},
		{
			name: "ok: package exists at latest",
			r: &Report{
				Modules: []*Module{
					{
						Module: "golang.org/x/vulndb",
						Packages: []*Package{
							{
								Package: "golang.org/x/vulndb/cmd/vulnreport",
							},
						},
					},
				},
			},
		},
		{
			name: "ok: package exists at vulnerable_at",
			r: &Report{
				Modules: []*Module{
					{
						Module:       "golang.org/x/vulndb",
						VulnerableAt: VulnerableAt("0.0.0-20240515145110-57274b497de9"),
						Packages: []*Package{
							{
								// This package was deleted but it exists at the
								// vulnerable_at version.
								Package: "golang.org/x/vulndb/internal/cveschema",
							},
						},
					},
				},
			},
		},
		{
			name: "ok: std and cmd packages",
			r: &Report{
				Modules: []*Module{
					{
						Module: "std",
						Packages: []*Package{
							{
								Package: "net/http",
							},
						},
					},
					{
						Module: "cmd",
						Packages: []*Package{
							{
								Package: "cmd/go",
							},
						},
					},
				},
			},
		},
		{
			name: "error: package does not exist",
			r: &Report{
				Modules: []*Module{
					{
						Module:       "golang.org/x/vulndb",
						VulnerableAt: VulnerableAt("0.0.0-20240515145110-57274b497de9"),
						Packages: []*Package{
							{
								Package: "golang.org/x/vulndb/internal/cveschema3",
							},
						},
					},
				},
			},
			wantErr: errPackageNotExist,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			err := tc.r.CheckPackages(ctx, pkc)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("CheckPackages: err = %v, want = %v", err, tc.wantErr)
			}
		})
	}
}
