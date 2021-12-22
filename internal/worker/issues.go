// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"fmt"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"golang.org/x/vulndb/internal"
	"golang.org/x/vulndb/internal/derrors"
)

type Issue struct {
	Title  string
	Body   string
	Labels []string
}

type IssueClient interface {
	// Destination describes where issues will be created.
	Destination() string

	// Reference returns a string that refers to the issue with number.
	Reference(number int) string

	// IssueExists reports whether an issue with the given ID exists.
	IssueExists(ctx context.Context, number int) (bool, error)

	// CreateIssue creates a new issue.
	CreateIssue(ctx context.Context, iss *Issue) (number int, err error)

	// GetIssue returns an issue with the given issue number.
	GetIssue(ctx context.Context, number int) (iss *Issue, err error)
}

// ParseGithubRepo parses a string of the form owner/repo.
func ParseGithubRepo(s string) (owner, repoName string, err error) {
	var found bool
	owner, repoName, found = internal.Cut(s, "/")
	if !found {
		return "", "", fmt.Errorf("%q is not in the form owner/repo", s)
	}
	return owner, repoName, nil
}

type githubIssueClient struct {
	client *github.Client
	owner  string
	repo   string
}

// NewGithubIssueClient creates an IssueClient that will create issues in
// the a GitHub repo.
// A GitHub access token is required to create issues.
func NewGithubIssueClient(owner, repo, accessToken string) *githubIssueClient {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	tc := oauth2.NewClient(context.Background(), ts)
	return &githubIssueClient{
		client: github.NewClient(tc),
		owner:  owner,
		repo:   repo,
	}
}

// Destination implements IssueClient.Destination.
func (c *githubIssueClient) Destination() string {
	return fmt.Sprintf("https://github.com/%s/%s", c.owner, c.repo)
}

// Reference implements IssueClient.Reference.
func (c *githubIssueClient) Reference(num int) string {
	return fmt.Sprintf("%s/issues/%d", c.Destination(), num)
}

// IssueExists implements IssueClient.IssueExists.
func (c *githubIssueClient) IssueExists(ctx context.Context, number int) (_ bool, err error) {
	defer derrors.Wrap(&err, "IssueExists(%d)", number)

	iss, _, err := c.client.Issues.Get(ctx, c.owner, c.repo, number)
	if err != nil {
		return false, err
	}
	if iss != nil {
		fmt.Printf("ID = %d, Number = %d\n", iss.GetID(), iss.GetNumber())
		return true, nil
	}
	return false, nil
}

func (c *githubIssueClient) GetIssue(ctx context.Context, number int) (_ *Issue, err error) {
	defer derrors.Wrap(&err, "GetIssue(%d)", number)
	iss, _, err := c.client.Issues.Get(ctx, c.owner, c.repo, number)
	if err != nil {
		return nil, err
	}
	r := &Issue{}
	if iss.Title != nil {
		r.Title = *iss.Title
	}
	if iss.Body != nil {
		r.Body = *iss.Body
	}
	return r, nil
}

// CreateIssue implements IssueClient.CreateIssue.
func (c *githubIssueClient) CreateIssue(ctx context.Context, iss *Issue) (number int, err error) {
	defer derrors.Wrap(&err, "CreateIssue(%s)", iss.Title)

	req := &github.IssueRequest{
		Title:  &iss.Title,
		Body:   &iss.Body,
		Labels: &iss.Labels,
	}
	giss, _, err := c.client.Issues.Create(ctx, c.owner, c.repo, req)
	if err != nil {
		return 0, err
	}
	return giss.GetNumber(), nil
}
