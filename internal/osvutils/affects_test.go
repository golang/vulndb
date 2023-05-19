// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osvutils

import (
	"errors"
	"testing"

	"golang.org/x/vulndb/internal/osv"
)

func TestAffectsSemver(t *testing.T) {
	tests := []struct {
		name    string
		Ranges  []osv.Range
		version string
		want    bool
	}{
		{
			name:    "single introduced:0",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}}}},
			version: "10.0.0",
			want:    true,
		},
		{
			// 1.0.0 < 2.0.0
			name:    "inside osv.Range with introduced=0<v<fixed",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
			version: "1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0
			name:    "inside osv.Range with introduced<v",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}}}},
			version: "1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0
			name:    "inside osv.Range with introduced=v",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}}}},
			version: "1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0 < v2.0.0
			name:    "inside osv.Range with introduced=v<fixed",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0 < v2.0.0
			name:    "inside osv.Range with introduced<v<fixed",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.0"}}}},
			version: "1.0.0",
			want:    true,
		},
		{
			// v2.0.0 < v3.0.0
			name:    "outside osv.Range with introduced<fixed<v",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "3.0.0",
			want:    false,
		},
		{
			// v1.0.0 < v2.0.0
			name:    "outside osv.Range with v<introduced<fixed",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "2.0.0"}, {Fixed: "3.0.0"}}}},
			version: "1.0.0",
			want:    false,
		},
		{
			name:    "inside osv.Range with multiple Ranges",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}, {Introduced: "3.0.0"}}}},
			version: "3.0.0",
			want:    true,
		},
		{
			name:    "outside osv.Range with multiple Ranges",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "1.18.6"}, {Introduced: "1.19.0"}, {Fixed: "1.19.1"}}}},
			version: "1.18.6",
			want:    false,
		},
		{
			// pseudo-versions work
			name: "pseudo-version",
			Ranges: []osv.Range{
				{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.0-20210824120805-abcdef"}}},
			},
			version: "0.0.0-20220824120805-4b6e5c587895",
			want:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := AffectsSemver(test.Ranges, test.version)
			if err != nil {
				t.Fatal(err)
			}
			if test.want != got {
				t.Errorf("AffectsSemver(%#v, %s): want %t, got %t", test.Ranges, test.version, test.want, got)
			}
		})
	}
}

func TestAffectsSemverError(t *testing.T) {
	tests := []struct {
		name    string
		Ranges  []osv.Range
		version string
		wantErr error
	}{
		{
			name:    "unsorted range",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}, {Introduced: "1.2.0"}}}},
			version: "0.0.0",
			wantErr: errUnsortedRange,
		},
		{
			name:    "invalid version",
			Ranges:  []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "v0.0.0",
			wantErr: errInvalidSemver,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, got := AffectsSemver(test.Ranges, test.version)
			if !errors.Is(got, test.wantErr) {
				t.Errorf("AffectsSemver(%#v, %s): want err containing %q, got %q", test.Ranges, test.version, test.wantErr, got)
			}
		})
	}
}
