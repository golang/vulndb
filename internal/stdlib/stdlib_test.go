// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stdlib

import "testing"

func TestContains(t *testing.T) {
	for _, test := range []struct {
		in   string
		want bool
	}{
		{"", false},
		{"math/crypto", true},
		{"github.com/pkg/errors", false},
		{"Path is unknown", false},
	} {
		got := Contains(test.in)
		if got != test.want {
			t.Errorf("%q: got %t, want %t", test.in, got, test.want)
		}
	}
}
