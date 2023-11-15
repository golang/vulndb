// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLinter(t *testing.T) {
	l := NewLinter("")

	l.Error("an error")
	g1 := l.Group("group1")
	g1.Error("a group error")
	g2 := g1.Group("group2")

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		l.Error("an error in a goroutine")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		g3 := l.Group("group3")
		g3.Error("an error in a group created in a goroutine")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		l.Errorf("a formatted %s", "error")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		g2.Errorf("a formatted inner group error (group %d)", 2)
	}()

	wg.Wait()

	want := []string{
		"an error",
		"group1: a group error",
		"an error in a goroutine",
		"group3: an error in a group created in a goroutine",
		"a formatted error",
		"group1: group2: a formatted inner group error (group 2)",
	}
	got := l.Errors()
	if diff := cmp.Diff(want, got, cmpopts.SortSlices(
		func(a, b string) bool { return a < b })); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
