// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"testing"

	"golang.org/x/mod/semver"
)

func TestLatestVersion(t *testing.T) {
	got, err := latestVersion(context.Background(), "golang.org/x/build")
	if err != nil {
		t.Fatal(err)
	}
	if !semver.IsValid(got) {
		t.Errorf("got invalid version %q", got)
	}
}

func TestLatestTaggedVersion(t *testing.T) {
	got, err := latestTaggedVersion(context.Background(), "golang.org/x/build")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf(`got %q, wanted ""`, got)
	}

	got, err = latestTaggedVersion(context.Background(), "golang.org/x/tools")
	if err != nil {
		t.Fatal(err)
	}
	if !semver.IsValid(got) {
		t.Errorf("got invalid version %q", got)
	}

}

func TestModuleZip(t *testing.T) {
	ctx := context.Background()
	const m = "golang.org/x/time"
	v, err := latestVersion(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = moduleZip(ctx, m, v)
	if err != nil {
		t.Fatal(err)
	}
}
