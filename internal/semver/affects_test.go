// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package semver

import (
	"testing"

	"golang.org/x/vulndb/internal/osv"
)

func TestAffectsSemver(t *testing.T) {
	cases := []struct {
		affects []osv.Range
		version string
		want    bool
	}{
		{
			// empty ranges indicates everything is affected
			affects: []osv.Range{},
			version: "v0.0.0",
			want:    true,
		},
		{
			// ranges containing an empty SEMVER range also indicates
			// everything is affected
			affects: []osv.Range{{Type: osv.RangeTypeSemver}},
			version: "v0.0.0",
			want:    true,
		},
		{
			// ranges containing a SEMVER range with only an "introduced":"0"
			// also indicates everything is affected
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}}}},
			version: "v0.0.0",
			want:    true,
		},
		{
			// v1.0.0 < v2.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v1.0.0 <= v1.0.0 < v2.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v0.0.1 <= v1.0.0 < v2.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.0"}}}},
			version: "v1.0.0",
			want:    true,
		},
		{
			// v2.0.0 < v3.0.0
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Multiple ranges
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}, {Introduced: "3.0.0"}}}},
			version: "v3.0.0",
			want:    true,
		},
		{
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "1.18.6"}, {Introduced: "1.19.0"}, {Fixed: "1.19.1"}}}},
			version: "v1.18.6",
			want:    false,
		},
		{
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Introduced: "1.19.0"}, {Fixed: "1.19.1"}}}},
			version: "v1.18.6",
			want:    true,
		},
		{
			// Multiple non-sorted ranges.
			affects: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.19.0"}, {Fixed: "1.19.1"}, {Introduced: "0"}, {Fixed: "1.18.6"}}}},
			version: "v1.18.1",
			want:    true,
		},
		{
			// Wrong type range
			affects: []osv.Range{{Type: osv.RangeType("unspecified"), Events: []osv.RangeEvent{{Introduced: "3.0.0"}}}},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges don't match
			affects: []osv.Range{
				{Type: osv.RangeType("unspecified"), Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
				{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "4.0.0"}}},
			},
			version: "v3.0.0",
			want:    false,
		},
		{
			// Semver ranges do match
			affects: []osv.Range{
				{Type: osv.RangeType("unspecified"), Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
				{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
			},
			version: "v3.0.0",
			want:    true,
		},
		{
			// Semver ranges match (go prefix)
			affects: []osv.Range{
				{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "3.0.0"}}},
			},
			version: "go3.0.1",
			want:    true,
		},
	}
	for _, c := range cases {
		got := AffectsSemver(c.affects, c.version)
		if c.want != got {
			t.Errorf("%#v.AffectsSemver(%s): want %t, got %t", c.affects, c.version, c.want, got)
		}
	}
}
