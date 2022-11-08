// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import "testing"

// TODO(https://github.com/golang/go#56417): Write unit tests for various
// invalid databases.

func TestValidate(t *testing.T) {
	if err := Validate(validDir); err != nil {
		t.Error(err)
	}
}
