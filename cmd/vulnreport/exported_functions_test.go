// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vulndb/internal/report"
)

func TestExportedFunctions(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "example.com/m",
			Files: map[string]interface{}{
				"p/a.go": `
					package p
					func vuln() {}
					func ok() {}
				`,
				"p/b.go": `
					package p

					import "example.com/m/internal/v"

					func Exp() { vuln() }
					func Trans() { Exp() }
					func Fine() { ok() }

					type D struct {}
					func (d D) Dep() {
						vl := v.V{}
						vl.Vuln()
					}
				`,
				"internal/v/v.go": `
					package v

					type V struct {}
					func (v V) Vuln() {}
				`,
			},
		},
	})
	defer e.Cleanup()

	m := &report.Module{
		Module: "example.com/m",
		Packages: []*report.Package{
			{
				Package: "example.com/m/p",
				Symbols: []string{"vuln"},
			},
			{
				Package: "example.com/m/internal/v",
				Symbols: []string{"V.Vuln"},
			},
		},
	}
	pkg, err := loadPackage(e.Config, path.Join(e.Temp(), "m/p"))
	if err != nil {
		t.Fatal(err)
	}
	// Clear Module.Dir so vulncheck doesn't think that the module is local and ignore it.
	// Set Module.Version so vulncheck doesn't filter it out.
	pkg.Module.Dir = ""
	pkg.Module.Version = "v1.0.0"

	got, err := exportedFunctions(pkg, m)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"Exp": true, "Trans": true, "D.Dep": true}
	if !cmp.Equal(got, want) {
		t.Errorf("\ngot\n\t%v\nwant\n\t%v", got, want)
	}
}
