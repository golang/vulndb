// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package issues

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/gitrepo"
)

var (
	githubRepo  = flag.String("repo", "", "GitHub repo (in form owner/repo) to test issues")
	githubToken = flag.String("ghtoken", os.Getenv("VULN_GITHUB_ACCESS_TOKEN"), "GitHub access token")
)

func diffIssue(want, got *Issue) string {
	return cmp.Diff(want, got,
		cmpopts.IgnoreFields(Issue{}, "CreatedAt"))
}
func diffIssues(want, got []*Issue) string {
	byTitle := func(a, b *Issue) bool { return a.Title < b.Title }
	return cmp.Diff(want, got, cmpopts.SortSlices(byTitle),
		cmpopts.IgnoreFields(Issue{}, "CreatedAt"))
}

func TestClient(t *testing.T) {
	t.Run("fake", func(t *testing.T) {
		testClient(t, NewFakeClient())
	})
	t.Run("github", func(t *testing.T) {
		if *githubRepo == "" {
			t.Skip("skipping: no -repo flag")
		}
		owner, repo, err := gitrepo.ParseGitHubRepo(*githubRepo)
		if err != nil {
			t.Fatal(err)
		}
		if *githubToken == "" {
			t.Fatal("need -ghtoken")
		}
		testClient(t, NewGitHubClient(owner, repo, *githubToken))
	})
}

func testClient(t *testing.T, c Client) {
	ctx := context.Background()
	iss := &Issue{
		Title:  "vuln worker test",
		Body:   "test of go.googlesource.com/vulndb/internal/issues",
		Labels: []string{"testing"},
		State:  "open",
	}
	iss2 := &Issue{
		Title:  "vuln worker test2",
		Body:   "test of go.googlesource.com/vulndb/internal/issues",
		Labels: []string{"testing", "other"},
		State:  "open",
	}

	num, err := c.CreateIssue(ctx, iss)
	iss.Number = num
	if err != nil {
		t.Fatal(err)
	}
	gotExists, err := c.IssueExists(ctx, num)
	if err != nil {
		t.Fatal(err)
	}
	if !gotExists {
		t.Error("created issue doesn't exist")
	}
	gotIss, err := c.GetIssue(ctx, num)
	if err != nil {
		t.Fatal(err)
	}
	if diff := diffIssue(iss, gotIss); diff != "" {
		fmt.Printf("%v", *gotIss)
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
	num2, err := c.CreateIssue(ctx, iss2)
	iss2.Number = num2
	if err != nil {
		t.Fatal(err)
	}

	want := []*Issue{iss, iss2}
	got, err := c.GetIssues(ctx, GetIssuesOptions{Labels: []string{"testing"}})
	if err != nil {
		t.Fatal(err)
	}

	if diff := diffIssues(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
	want = []*Issue{iss2}
	got, err = c.GetIssues(ctx, GetIssuesOptions{Labels: []string{"other"}})
	if err != nil {
		t.Fatal(err)
	}

	if diff := diffIssues(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
