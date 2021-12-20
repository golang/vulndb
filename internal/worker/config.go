// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"errors"

	"golang.org/x/vulndb/internal/worker/store"
)

// serviceID names the Cloud Run service.
const serviceID = "vuln-worker"

// Config holds configuration information for the worker server.
type Config struct {
	// Project is the Google Cloud Project where the resources live.
	Project string

	// Namespace is the Firstore namespace to use.
	Namespace string

	// UseErrorReporting determines whether errors go to the Error Reporting API.
	UseErrorReporting bool

	// IssueRepo is the GitHub repo to use for issues.
	// An empty string disables issue creation.
	IssueRepo string

	// GitHubAccessToken is the token needed to authorize to the GitHub API.
	GitHubAccessToken string

	// Store is the implementation of store.Store used by the server.
	Store store.Store
}

func (c *Config) Validate() error {
	if c.Project == "" {
		return errors.New("missing project")
	}
	if c.Namespace == "" {
		return errors.New("missing namespace")
	}
	if c.IssueRepo != "" && c.GitHubAccessToken == "" {
		return errors.New("issue repo requires access token")
	}
	return nil
}
