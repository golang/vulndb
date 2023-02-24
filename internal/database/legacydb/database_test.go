// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package legacydb

import (
	"context"
	"flag"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/gitrepo"
)

var (
	integration = flag.Bool("integration", false, "test with respect to current contents of vulndb")

	testRepoDir = "testdata/repo.txtar"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	testRepo, err := gitrepo.ReadTxtarRepo(testRepoDir, jan2002)
	if err != nil {
		t.Fatal(err)
	}
	got, err := New(ctx, testRepo)
	if err != nil {
		t.Fatal(err)
	}
	want := valid
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected diff (want-, got+):\n%s", diff)
	}
}

func TestAll(t *testing.T) {
	ctx := context.Background()
	testRepo, err := gitrepo.ReadTxtarRepo(testRepoDir, jan2002)
	if err != nil {
		t.Fatal(err)
	}
	new, err := New(ctx, testRepo)
	if err != nil {
		t.Fatal(err)
	}

	writeDir := t.TempDir()
	if err = new.Write(writeDir, true); err != nil {
		t.Fatal(err)
	}
	if err = cmpDirHashes(validDir, writeDir); err != nil {
		t.Error(err)
	}

	validated, err := Load(writeDir)
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(validated, new); diff != "" {
		t.Errorf("unexpected diff (validated-, new+):\n%s", diff)
	}
}

func TestAllIntegration(t *testing.T) {
	if !*integration {
		t.Skip("Skipping integration tests, use flag -integration to run")
	}

	ctx := context.Background()

	repo, err := gitrepo.Open(ctx, "../..")
	if err != nil {
		t.Fatal(err)
	}
	new, err := New(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	writeDir := t.TempDir()
	if err = new.Write(writeDir, true); err != nil {
		t.Fatal(err)
	}

	validated, err := Load(writeDir)
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(validated, new); diff != "" {
		t.Errorf("unexpected diff (validated-, new+):\n%s", diff)
	}
}
