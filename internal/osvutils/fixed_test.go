// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osvutils

import (
	"testing"

	"golang.org/x/vulndb/internal/osv"
)

func TestLatestFixed(t *testing.T) {
	tests := []struct {
		name   string
		ranges []osv.Range
		want   string
	}{
		{
			name:   "empty",
			ranges: []osv.Range{},
			want:   "",
		},
		{
			name: "no fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Introduced: "0",
					},
				},
			}},
			want: "",
		},
		{
			name: "no latest fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{Introduced: "0"},
					{Fixed: "1.0.4"},
					{Introduced: "1.1.2"},
				},
			}},
			want: "",
		},
		{
			name: "unsorted no latest fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{Fixed: "1.0.4"},
					{Introduced: "0"},
					{Introduced: "1.1.2"},
					{Introduced: "1.5.0"},
					{Fixed: "1.1.4"},
				},
			}},
			want: "",
		},
		{
			name: "unsorted with fix",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Fixed: "1.0.0",
					},
					{
						Introduced: "0",
					},
					{
						Fixed: "0.1.0",
					},
					{
						Introduced: "0.5.0",
					},
				},
			}},
			want: "1.0.0",
		},
		{
			name: "multiple ranges",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Introduced: "0",
					},
					{
						Fixed: "0.1.0",
					},
				},
			},
				{
					Type: osv.RangeTypeSemver,
					Events: []osv.RangeEvent{
						{
							Introduced: "0",
						},
						{
							Fixed: "0.2.0",
						},
					},
				}},
			want: "0.2.0",
		},
		{
			name: "pseudoversion",
			ranges: []osv.Range{{
				Type: osv.RangeTypeSemver,
				Events: []osv.RangeEvent{
					{
						Introduced: "0",
					},
					{
						Fixed: "0.0.0-20220824120805-abc",
					},
					{
						Introduced: "0.0.0-20230824120805-efg",
					},
					{
						Fixed: "0.0.0-20240824120805-hij",
					},
				},
			}},
			want: "0.0.0-20240824120805-hij",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := LatestFixed(test.ranges)
			if got != test.want {
				t.Errorf("LatestFixed = %q, want %q", got, test.want)
			}
		})
	}
}
