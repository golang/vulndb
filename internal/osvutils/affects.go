// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osvutils

import (
	"fmt"

	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/version"
)

// AffectsSemver returns whether the version v is within the given ranges.
// v must be unprefixed, valid semver, and ranges must be sorted,
// non-overlapping, and contain only valid semver.
// The function errors if either of the inputs is invalid.
func AffectsSemver(ranges []osv.Range, v string) (bool, error) {
	// Check that ranges are sorted and otherwise valid.
	if err := validateRanges(ranges); err != nil {
		return false, err
	}
	if !version.IsValid(v) {
		return false, fmt.Errorf("%w: %s", errInvalidSemver, v)
	}
	for _, r := range ranges {
		if containsSemver(r, v) {
			return true, nil
		}
	}
	return false, nil
}

// containsSemver checks if semver version v is in the
// range encoded by ar.
// The range must be sorted in ascending order.
func containsSemver(ar osv.Range, v string) bool {
	var affected bool
	for _, e := range ar.Events {
		if !affected && e.Introduced != "" {
			affected = e.Introduced == "0" || !version.Before(v, e.Introduced)
		} else if affected && e.Fixed != "" {
			affected = version.Before(v, e.Fixed)
		}
	}
	return affected
}
