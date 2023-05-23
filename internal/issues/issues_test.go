// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package issues_test

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/issues/githubtest"
)

var testConfig = &issues.Config{
	Owner: githubtest.TestOwner,
	Repo:  githubtest.TestRepo,
	Token: githubtest.TestToken,
}

func TestClient(t *testing.T) {
	client, _ := githubtest.Setup(context.Background(), t, testConfig)
	want := fmt.Sprintf("https://github.com/%s/%s", githubtest.TestOwner, githubtest.TestRepo)
	if got := client.Destination(); got != want {
		t.Fatalf("client.Destination(): %q; want = %q", got, want)
	}
	want = fmt.Sprintf("https://github.com/%s/%s/issues/2", githubtest.TestOwner, githubtest.TestRepo)
	if got := client.Reference(2); got != want {
		t.Fatalf("client.Reference(): %q; want = %q", got, want)
	}
}

func TestCreateIssue(t *testing.T) {
	c, mux := githubtest.Setup(context.Background(), t, testConfig)
	want := 15
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/issues", githubtest.TestOwner, githubtest.TestRepo), func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		fmt.Fprintf(w, `{"number":%d}`, want)
	})
	ctx := context.Background()
	input := &issues.Issue{Title: "title", Body: "body"}
	got, err := c.CreateIssue(ctx, input)
	if err != nil {
		t.Fatalf("c.CreateIssue: %v", err)
	}
	if got != want {
		t.Errorf("c.CreateIssue(ctx, %v) = %d; got = %d", input, got, want)
	}
}

func TestIssueAndIssueExists(t *testing.T) {
	c, mux := githubtest.Setup(context.Background(), t, testConfig)
	want := &issues.Issue{
		Number: 7,
		Title:  "title",
		Body:   "body",
	}
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/issues/%d", githubtest.TestOwner, githubtest.TestRepo, want.Number), func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		if strings.HasSuffix(r.URL.Path, strconv.Itoa(want.Number)) {
			fmt.Fprintf(w, `{"number":%d, "title":%q, "body":%q}`, want.Number, want.Title, want.Body)
			return
		}
	})
	ctx := context.Background()
	got, err := c.Issue(ctx, want.Number)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected diff (want-, got+):\n%s", diff)
	}
	got2, err := c.IssueExists(ctx, want.Number)
	if err != nil {
		t.Fatal(err)
	}
	if !got2 {
		t.Errorf("c.IssueExist(ctx, %d) = %t; want = true", want.Number, got2)
	}
}

func TestIssues(t *testing.T) {
	c, mux := githubtest.Setup(context.Background(), t, testConfig)
	iss := &issues.Issue{
		Number: 1,
		Title:  "vuln worker test",
		Body:   "test of go.googlesource.com/vulndb/internal/issues",
		State:  "open",
	}
	iss2 := &issues.Issue{
		Number: 2,
		Title:  "vuln worker test2",
		Body:   "test of go.googlesource.com/vulndb/internal/issues",
		State:  "open",
	}
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/issues", githubtest.TestOwner, githubtest.TestRepo), func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		fmt.Fprintf(w, `[{"number":%d, "title":%q, "body":%q, "state":%q},{"number":%d, "title":%q, "body":%q, "state":%q}]`,
			iss.Number, iss.Title, iss.Body, iss.State, iss2.Number, iss2.Title, iss2.Body, iss2.State)
	})
	ctx := context.Background()
	want := []*issues.Issue{iss, iss2}
	got, err := c.Issues(ctx, issues.IssuesOptions{State: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if diff := diffIssues(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func testMethod(t *testing.T, r *http.Request, want string) {
	t.Helper()
	if got := r.Method; got != want {
		t.Errorf("Request method: %v, want %v", got, want)
	}
}

func diffIssues(want, got []*issues.Issue) string {
	byTitle := func(a, b *issues.Issue) bool { return a.Title < b.Title }
	return cmp.Diff(want, got, cmpopts.SortSlices(byTitle),
		cmpopts.IgnoreFields(issues.Issue{}, "CreatedAt"))
}
