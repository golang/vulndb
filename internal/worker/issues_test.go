// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package worker

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

var (
	githubRepo      = flag.String("repo", "", "GitHub repo (in form owner/repo) to test issues")
	githubTokenFile = flag.String("ghtokenfile", "", "path to file containing GitHub access token")
)

func TestIssueClient(t *testing.T) {
	t.Run("fake", func(t *testing.T) {
		testIssueClient(t, newFakeIssueClient())
	})
	t.Run("github", func(t *testing.T) {
		if *githubRepo == "" {
			t.Skip("skipping: no -repo flag")
		}
		owner, repo, err := ParseGithubRepo(*githubRepo)
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
		testIssueClient(t, NewGithubIssueClient(owner, repo, token))
	})
}

func testIssueClient(t *testing.T, c IssueClient) {
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

type fakeIssueClient struct {
	nextID int
	issues map[int]*Issue
}

func newFakeIssueClient() *fakeIssueClient {
	return &fakeIssueClient{
		nextID: 1,
		issues: map[int]*Issue{},
	}
}

func (c *fakeIssueClient) Destination() string {
	return "in memory"
}

func (c *fakeIssueClient) Reference(num int) string {
	return fmt.Sprintf("inMemory#%d", num)
}

func (c *fakeIssueClient) IssueExists(_ context.Context, number int) (bool, error) {
	_, ok := c.issues[number]
	return ok, nil
}

func (c *fakeIssueClient) CreateIssue(_ context.Context, iss *Issue) (number int, err error) {
	number = c.nextID
	c.nextID++
	copy := *iss
	c.issues[number] = &copy
	return number, nil
}
