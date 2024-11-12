// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osvutils

import (
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/version"
)

func LatestFixed(ranges []osv.Range) string {
	var latestFixed string
	for _, r := range ranges {
		if r.Type == osv.RangeTypeSemver {
			for _, e := range r.Events {
				if fixed := e.Fixed; fixed != "" && version.Before(latestFixed, fixed) {
					latestFixed = fixed
				}
			}
			// If the vulnerability was re-introduced after the latest fix
			// we found, there is no latest fix for this range.
			for _, e := range r.Events {
				if introduced := e.Introduced; introduced != "" && introduced != "0" && version.Before(latestFixed, introduced) {
					latestFixed = ""
					break
				}
			}
		}
	}
	return string(latestFixed)
}
