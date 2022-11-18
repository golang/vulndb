// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package issues provides a general way to interact with issues,
// and a client for interacting with the GitHub  issues API.
package issues

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-github/v41/github"
	"golang.org/x/oauth2"
	"golang.org/x/vulndb/internal/derrors"
)

// An Issue represents a GitHub issue or similar.
type Issue struct {
	Number    int
	Title     string
	Body      string
	State     string
	Labels    []string
	CreatedAt time.Time
}

// GetIssuesOptions are options for GetIssues
type GetIssuesOptions struct {
	// State filters issues based on their state. Possible values are: open,
	// closed, all. Default is "open".
	State string

	// Labels filters issues based on their label.
	Labels []string
}

// Client is a client that can create and retrieve issues.
type Client interface {
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

	GetIssues(ctx context.Context, opts GetIssuesOptions) (issues []*Issue, err error)
}

type githubClient struct {
	client *github.Client
	owner  string
	repo   string
}

// NewGitHubClient creates a Client that will create issues in
// the a GitHub repo.
// A GitHub access token is required to create issues.
func NewGitHubClient(owner, repo, accessToken string) *githubClient {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	tc := oauth2.NewClient(context.Background(), ts)
	return &githubClient{
		client: github.NewClient(tc),
		owner:  owner,
		repo:   repo,
	}
}

// Destination implements Client.Destination.
func (c *githubClient) Destination() string {
	return fmt.Sprintf("https://github.com/%s/%s", c.owner, c.repo)
}

// Reference implements Client.Reference.
func (c *githubClient) Reference(num int) string {
	return fmt.Sprintf("%s/issues/%d", c.Destination(), num)
}

// IssueExists implements Client.IssueExists.
func (c *githubClient) IssueExists(ctx context.Context, number int) (_ bool, err error) {
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

// convertGithubIssueToIssue converts the github.Issue type to our Issue type
func convertGithubIssueToIssue(ghIss *github.Issue) *Issue {
	iss := &Issue{}
	if ghIss.Number != nil {
		iss.Number = *ghIss.Number
	}
	if ghIss.Title != nil {
		iss.Title = *ghIss.Title
	}
	if ghIss.Number != nil {
		iss.Number = *ghIss.Number
	}
	if ghIss.Body != nil {
		iss.Body = *ghIss.Body
	}
	if ghIss.CreatedAt != nil {
		iss.CreatedAt = *ghIss.CreatedAt
	}
	if ghIss.State != nil {
		iss.State = *ghIss.State
	}
	if ghIss.Labels != nil {
		iss.Labels = make([]string, len(ghIss.Labels))
		for i, label := range ghIss.Labels {
			iss.Labels[i] = label.GetName()
		}
	}
	return iss
}

// GetIssue implements Client.GetIssue.
func (c *githubClient) GetIssue(ctx context.Context, number int) (_ *Issue, err error) {
	defer derrors.Wrap(&err, "GetIssue(%d)", number)
	ghIss, _, err := c.client.Issues.Get(ctx, c.owner, c.repo, number)
	if err != nil {
		return nil, err
	}
	iss := convertGithubIssueToIssue(ghIss)

	return iss, nil
}

// GetIssues implements Client.GetIssues
func (c *githubClient) GetIssues(ctx context.Context, opts GetIssuesOptions) (_ []*Issue, err error) {
	defer derrors.Wrap(&err, "GetIssues()")
	clientOpts := &github.IssueListByRepoOptions{
		State:  opts.State,
		Labels: opts.Labels,
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	issues := []*Issue{}
	page := 1

	for {
		clientOpts.ListOptions.Page = page
		pageIssues, resp, err := c.client.Issues.ListByRepo(ctx, c.owner, c.repo, clientOpts)
		if err != nil {
			return nil, err
		}
		for _, giss := range pageIssues {
			issues = append(issues, convertGithubIssueToIssue(giss))
		}
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	return issues, nil
}

// CreateIssue implements Client.CreateIssue.
func (c *githubClient) CreateIssue(ctx context.Context, iss *Issue) (number int, err error) {
	defer derrors.Wrap(&err, "CreateIssue(%s)", iss.Title)

	req := &github.IssueRequest{
		Title: &iss.Title,
		Body:  &iss.Body,
	}
	if len(iss.Labels) > 0 {
		req.Labels = &iss.Labels
	}
	giss, _, err := c.client.Issues.Create(ctx, c.owner, c.repo, req)
	if err != nil {
		return 0, err
	}
	return giss.GetNumber(), nil
}

// NewGoID creates a Go advisory ID based on the issue number
// and time of issue creation.
func (iss *Issue) NewGoID() string {
	var year int
	if !iss.CreatedAt.IsZero() {
		year = iss.CreatedAt.Year()
	}
	return fmt.Sprintf("GO-%04d-%04d", year, iss.Number)
}
