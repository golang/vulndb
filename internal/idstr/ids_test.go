// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package idstr

import "testing"

func TestFindCVE(t *testing.T) {
	s := "something/CVE-1999-0004.json"
	got, want := FindCVE(s), "CVE-1999-0004"
	if got != want {
		t.Errorf("FindCVE(%s) = %s, want %s", s, got, want)
	}
}
