// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/gitrepo"
)

var integration = flag.Bool("integration", false, "test with respect to current contents of vulndb")

func TestNewWriteLoadValidate(t *testing.T) {
	newDB, err := New(testOSV1, testOSV2, testOSV3)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err = newDB.Write(tmpDir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(newDB, loaded); diff != "" {
		t.Errorf("new/write/load mismatch (-new, +loaded):\n%s", diff)
	}
	if err := ValidateDeploy(tmpDir, tmpDir); err != nil {
		t.Error(err)
	}
}

func TestFromRepoWriteLoadValidate(t *testing.T) {
	ctx := context.Background()
	testRepo, err := gitrepo.ReadTxtarRepo(vulndbTxtar, jan2002.Time)
	if err != nil {
		t.Fatal(err)
	}

	fromRepo, err := FromRepo(ctx, testRepo)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err = fromRepo.Write(tmpDir); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(fromRepo, loaded); diff != "" {
		t.Errorf("fromRepo/write/load mismatch (-fromRepo, +loaded):\n%s", diff)
	}
	if err := ValidateDeploy(tmpDir, tmpDir); err != nil {
		t.Error(err)
	}
}

func TestIntegration(t *testing.T) {
	if !*integration {
		t.Skip("Skipping integration tests, use flag -integration to run")
	}

	moveToVulnDBRoot(t)

	ctx := context.Background()

	repo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	created, err := FromRepo(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	if err := created.Write(dir); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(created, loaded); diff != "" {
		t.Errorf("unexpected diff: (-created,+loaded):\n%s", diff)
	}

	if err := ValidateDeploy(dir, dir); err != nil {
		t.Error(err)
	}
}

func moveToVulnDBRoot(t *testing.T) {
	// Store current working directory and move into vulndb/ folder.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}

	// Restore state from before test.
	t.Cleanup(func() {
		if err = os.Chdir(wd); err != nil {
			t.Log(err)
		}
	})
}
