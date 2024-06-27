// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import "strings"

// Hard-coded list of words we've had problems with in the past.
var replacer = strings.NewReplacer(
	"expropiation", "expropriation",
	"Constallation", "Constellation",
)

func fixSpelling(s string) string {
	return replacer.Replace(s)
}
