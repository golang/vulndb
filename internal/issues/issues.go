// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package issues provides a general way to interact with issues,
// and a client for interacting with the GitHub  issues API.
package issues

import (
	"context"
	"fmt"
	"net/url"
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
type Client struct {
	client *github.Client
	owner  string
	repo   string
}

// Config is used to initialize a new Client.
type Config struct {
	// Owner is the owner of a GitHub repo. For example, "golang" is the owner
	// for github.com/golang/vulndb.
	Owner string

	// Repo is the name of a GitHub repo. For example, "vulndb" is the repo
	// name for github.com/golang/vulndb.
	Repo string

	// Token is access token that authorizes and authenticates
	// requests to the GitHub API.
	Token string
}

// NewClient creates a Client that will create issues in
// the a GitHub repo.
func NewClient(cfg *Config) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
	tc := oauth2.NewClient(context.Background(), ts)
	c := github.NewClient(tc)
	return &Client{
		client: c,
		owner:  cfg.Owner,
		repo:   cfg.Repo,
	}
}

// NewTestClient creates a Client for use in tests.
func NewTestClient(cfg *Config, baseURL *url.URL) *Client {
	c := NewClient(cfg)
	c.client.BaseURL = baseURL
	c.client.UploadURL = baseURL
	return c
}

// Destination implements Client.Destination.
func (c *Client) Destination() string {
	return fmt.Sprintf("https://github.com/%s/%s", c.owner, c.repo)
}

// Reference implements Client.Reference.
func (c *Client) Reference(num int) string {
	return fmt.Sprintf("%s/issues/%d", c.Destination(), num)
}

// IssueExists implements Client.IssueExists.
func (c *Client) IssueExists(ctx context.Context, number int) (_ bool, err error) {
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
func (c *Client) GetIssue(ctx context.Context, number int) (_ *Issue, err error) {
	defer derrors.Wrap(&err, "GetIssue(%d)", number)
	ghIss, _, err := c.client.Issues.Get(ctx, c.owner, c.repo, number)
	if err != nil {
		return nil, err
	}
	iss := convertGithubIssueToIssue(ghIss)

	return iss, nil
}

// GetIssues implements Client.GetIssues
func (c *Client) GetIssues(ctx context.Context, opts GetIssuesOptions) (_ []*Issue, err error) {
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
func (c *Client) CreateIssue(ctx context.Context, iss *Issue) (number int, err error) {
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
