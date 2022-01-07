// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gitrepo_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/vulndb/internal/gitrepo"
)

func TestFileHistory(t *testing.T) {
	test := newTest(t)
	message := []string{"one", "two", "three"}
	for _, message := range message {
		test.Commit(message, map[string]string{
			"file": message,
		})

		// These commits touch other files, and should not be iterated over.
		test.Commit("other commit", map[string]string{
			"some_other_file": message,
		})
	}
	var got []string
	gitrepo.FileHistory(test.Repo, "file", func(commit *object.Commit) error {
		got = append([]string{strings.TrimSpace(commit.Message)}, got...)
		return nil
	})
	if !reflect.DeepEqual(got, message) {
		t.Errorf("got %v\nwant %v", got, message)
	}

}

type gitTest struct {
	t    *testing.T
	FS   billy.Filesystem
	Repo *git.Repository
}

func newTest(t *testing.T) *gitTest {
	t.Helper()
	mfs := memfs.New()
	repo, err := git.Init(memory.NewStorage(), mfs)
	if err != nil {
		t.Fatal(err)
	}
	return &gitTest{
		t:    t,
		FS:   mfs,
		Repo: repo,
	}
}

func (test *gitTest) Commit(message string, files map[string]string) {
	test.t.Helper()
	wt, err := test.Repo.Worktree()
	if err != nil {
		test.t.Fatal(err)
	}
	for name, content := range files {
		f, err := test.FS.Create(name)
		if err != nil {
			test.t.Fatal(err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			test.t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			test.t.Fatal(err)
		}
		if _, err := wt.Add(name); err != nil {
			test.t.Fatal(err)
		}
	}
	if _, err := wt.Commit(message, &git.CommitOptions{All: true, Author: &object.Signature{
		Name:  "Author",
		Email: "author@example.com",
	}}); err != nil {
		test.t.Fatal(err)
	}
}
