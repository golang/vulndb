// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package symbols

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

func TestPopulate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input *report.Report
		want  *report.Report
	}{
		{
			name: "basic",
			input: &report.Report{
				Modules: []*report.Module{{
					Module: "example.com/module",
				}},
				References: []*report.Reference{{
					Type: osv.ReferenceTypeFix,
					URL:  "https://example.com/module/commit/1234",
				}},
			},
			want: &report.Report{
				Modules: []*report.Module{{
					Module: "example.com/module",
					Packages: []*report.Package{{
						Package: "example.com/module/package",
						Symbols: []string{"symbol1", "symbol2"},
					}},
					FixLinks: []string{"https://example.com/module/commit/1234"},
				}},
				References: []*report.Reference{
					{
						Type: osv.ReferenceTypeFix,
						URL:  "https://example.com/module/commit/1234",
					},
				},
			},
		},
		{
			name: "multiple_fixes",
			input: &report.Report{
				Modules: []*report.Module{{
					Module: "example.com/module",
				}},
				References: []*report.Reference{
					{
						Type: osv.ReferenceTypeFix,
						URL:  "https://example.com/module/commit/1234",
					},
					{
						Type: osv.ReferenceTypeFix,
						URL:  "https://example.com/module/commit/5678",
					},
				},
			},
			want: &report.Report{
				Modules: []*report.Module{{
					Module: "example.com/module",
					Packages: []*report.Package{{
						Package: "example.com/module/package",
						// We don't yet dedupe the symbols.
						Symbols: []string{"symbol1", "symbol2", "symbol3"},
					}},
					// Both links are added because they both contain vulnerable symbols
					FixLinks: []string{"https://example.com/module/commit/1234", "https://example.com/module/commit/5678"},
				}},
				References: []*report.Reference{
					{
						Type: osv.ReferenceTypeFix,
						URL:  "https://example.com/module/commit/1234",
					},
					{
						Type: osv.ReferenceTypeFix,
						URL:  "https://example.com/module/commit/5678",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := populate(tc.input, patchedFake); err != nil {
				t.Fatal(err)
			}
			got := tc.input
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("populate mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func patchedFake(module string, repo string, hash string) (map[string][]string, error) {
	if module == "example.com/module" && repo == "https://example.com/module" && hash == "1234" {
		return map[string][]string{
			"example.com/module/package": {"symbol1", "symbol2"},
		}, nil
	}
	if module == "example.com/module" && repo == "https://example.com/module" && hash == "5678" {
		return map[string][]string{
			"example.com/module/package": {"symbol1", "symbol2", "symbol3"},
		}, nil
	}
	return nil, fmt.Errorf("unrecognized inputs: module=%s,repo=%s,hash=%s", module, repo, hash)
}
