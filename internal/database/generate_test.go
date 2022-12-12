// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/gitrepo"
)

func TestGenerate(t *testing.T) {
	ctx := context.Background()
	testRepo, err := gitrepo.ReadTxtarRepo(testRepoDir, jan2002)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	err = Generate(ctx, testRepo, tmpDir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = cmpDirHashes(tmpDir, validDir); err != nil {
		t.Error(err)
	}
}

func TestGenerateIntegration(t *testing.T) {
	if !*integration {
		t.Skip("Skipping integration tests, use flag -integration to run")
	}

	moveToVulnDBRoot(t)

	ctx := context.Background()

	repo, err := gitrepo.Open(ctx, ".")
	if err != nil {
		t.Fatal(err)
	}

	genDir := t.TempDir()
	err = Generate(ctx, repo, genDir, false)
	if err != nil {
		t.Fatal(err)
	}

	new, err := New(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Generate equivalent to New then Write", func(t *testing.T) {
		writeDir := t.TempDir()
		if err = new.Write(writeDir, false); err != nil {
			t.Fatal(err)
		}
		if err = cmpDirHashes(genDir, writeDir); err != nil {
			t.Error(err)
		}
	})

	t.Run("New equivalent to Generate then Load", func(t *testing.T) {
		loaded, err := Load(genDir)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(loaded, new); diff != "" {
			t.Errorf("unexpected diff (loaded-, new+):\n%s", diff)
		}
	})
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
