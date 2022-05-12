// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestLint(t *testing.T) {
	for _, test := range []struct {
		report Report
		want   []string
	}{{
		report: Report{
			Packages: []Package{{
				Module:  "std",
				Package: "time",
				Versions: []VersionRange{{
					Fixed: "1.2.1",
				}, {
					Fixed: "1.3.2",
				}},
			}},
		},
		want: []string{"version ranges overlap"},
	}, {
		report: Report{
			Packages: []Package{{
				Module:  "std",
				Package: "time",
				Versions: []VersionRange{{
					Introduced: "1.3",
					Fixed:      "1.2.1",
				}},
			}},
		},
		want: []string{`version "1.3" >= "1.2.1"`},
	}} {
		got := test.report.Lint()
		var missing []string
		for _, w := range test.want {
			found := false
			for _, g := range got {
				if strings.Contains(g, w) {
					found = true
					continue
				}
			}
			if !found {
				missing = append(missing, w)
			}
		}
		if len(missing) > 0 {
			var buf bytes.Buffer
			if err := test.report.encode(&buf); err != nil {
				t.Error(err)
			}
			t.Errorf("missing expected lint warnings in report:\n%v", buf.String())
			for _, g := range got {
				t.Errorf("  got:  %v", g)
			}
			for _, w := range missing {
				t.Errorf("  want: %v", w)
			}
		}
	}
}
