// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package legacydb

import (
	"context"
	"testing"

	db "golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/gitrepo"
)

func TestEquivalent(t *testing.T) {
	ctx := context.Background()
	testRepo, err := gitrepo.ReadTxtarRepo(testRepoDir, jan2002.Time)
	if err != nil {
		t.Fatal(err)
	}

	legacyDir := t.TempDir()
	err = Generate(ctx, testRepo, legacyDir, true)
	if err != nil {
		t.Fatal(err)
	}

	v1Dir := t.TempDir()
	v1, err := db.FromRepo(ctx, testRepo)
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.Write(v1Dir); err != nil {
		t.Fatal(err)
	}

	// Databases created from the same repo should be equivalent.
	if err := Equivalent(v1Dir, legacyDir); err != nil {
		t.Error(err)
	}

	// Equivalent should error because neither of the databases is
	// valid according to its schema.
	if err := Equivalent(legacyDir, v1Dir); err == nil {
		t.Error("Equivalent: got nil, want error")
	}
}

func TestCheckSameModulesAndVulns(t *testing.T) {
	legacy := newTestDB(testOSV1, testOSV2, testOSV3)
	v1, err := db.New(*testOSV1, *testOSV2)
	if err != nil {
		t.Fatal(err)
	}

	// Should error because legacy DB has an extra entry.
	if err := legacy.checkSameModulesAndVulns(v1); err == nil {
		t.Error("checkSameModulesAndVulns: got nil, want error")
	}

	if err := v1.Add(*testOSV3); err != nil {
		t.Error(err)
	}

	// Should now succeed.
	if err := legacy.checkSameModulesAndVulns(v1); err != nil {
		t.Error(err)
	}
}
