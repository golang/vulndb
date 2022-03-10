// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gitrepo_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/gitrepo"
)

func TestAllCommitDates(t *testing.T) {
	test := newTest(t)
	want := map[string]gitrepo.Dates{
		"files/1": gitrepo.Dates{
			Oldest: time.Date(2020, 1, 1, 1, 0, 0, 0, time.UTC),
			Newest: time.Date(2020, 1, 1, 1, 2, 0, 0, time.UTC),
		},
		"files/2": gitrepo.Dates{
			Oldest: time.Date(2020, 1, 1, 1, 1, 0, 0, time.UTC),
			Newest: time.Date(2020, 1, 1, 1, 3, 0, 0, time.UTC),
		},
	}
	for name, dates := range want {
		now := dates.Oldest
		for {
			if now.After(dates.Newest) {
				now = dates.Newest
			}
			test.Commit("message", now, map[string]string{
				name: fmt.Sprintf("commit at %v", now),
			})
			if now == dates.Newest {
				break
			}
			now = now.Add(1 * time.Hour)
		}
	}
	got, err := gitrepo.AllCommitDates(test.Repo, gitrepo.HeadReference, "files/")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("AllCommitDates returned unexpected result (-want,+got):\n%v", diff)
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

func (test *gitTest) Commit(message string, when time.Time, files map[string]string) {
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
		When:  when,
	}}); err != nil {
		test.t.Fatal(err)
	}
}
