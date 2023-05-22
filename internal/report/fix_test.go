// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFix(t *testing.T) {
	r := Report{
		Modules: []*Module{
			{
				Module: "std",
				Versions: []VersionRange{{
					Introduced: "go1.20",
					Fixed:      "go1.20.1",
				}},
				VulnerableAt: "go1.20",
			},
			{
				Module: "golang.org/x/vulndb",
				Versions: []VersionRange{{
					Introduced: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
				}},
				VulnerableAt: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
			},
		},
		References: []*Reference{
			{
				URL: "https://github.com/golang/go/issues/123",
			},
		},
	}
	want := Report{
		Modules: []*Module{
			{
				Module: "std",
				Versions: []VersionRange{{
					Introduced: "1.20.0",
					Fixed:      "1.20.1",
				}},
				VulnerableAt: "1.20.0",
			},
			{
				Module: "golang.org/x/vulndb",
				Versions: []VersionRange{{
					Introduced: "0.0.0-20230522180520-0cbf4ffdb4e7",
				}},
				VulnerableAt: "0.0.0-20230522180520-0cbf4ffdb4e7",
			},
		},
		References: []*Reference{
			{
				URL: "https://go.dev/issue/123",
			},
		},
	}

	r.Fix()

	got := r
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Fix() mismatch (-want +got):\n%s", diff)
	}
}
