// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package issues

import (
	"context"
	"flag"
	"io/ioutil"
	"strings"
	"testing"

	"golang.org/x/vulndb/internal"
)

var (
	githubRepo      = flag.String("repo", "", "GitHub repo (in form owner/repo) to test issues")
	githubTokenFile = flag.String("ghtokenfile", "", "path to file containing GitHub access token")
)

func TestClient(t *testing.T) {
	t.Run("fake", func(t *testing.T) {
		testClient(t, NewFakeClient())
	})
	t.Run("github", func(t *testing.T) {
		if *githubRepo == "" {
			t.Skip("skipping: no -repo flag")
		}
		owner, repo, err := internal.ParseGitHubRepo(*githubRepo)
		if err != nil {
			t.Fatal(err)
		}
		if *githubTokenFile == "" {
			t.Fatal("need -ghtokenfile")
		}
		data, err := ioutil.ReadFile(*githubTokenFile)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.TrimSpace(string(data))
		testClient(t, NewGitHubClient(owner, repo, token))
	})
}

func testClient(t *testing.T, c Client) {
	ctx := context.Background()
	iss := &Issue{
		Title:  "vuln worker test",
		Body:   "test of go.googlesource.com/vulndb/internal/worker",
		Labels: []string{"testing"},
	}
	num, err := c.CreateIssue(ctx, iss)
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
}
