// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/go-git/go-git/v5"
	"golang.org/x/vulndb/cmd/vulnreport/priority"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/proxy"
)

// environment stores fakes/mocks of external dependencies for testing.
type environment struct {
	reportRepo *git.Repository
	reportFS   fs.FS
	pc         *proxy.Client
	wfs        wfs
	ic         issueClient
	gc         ghsaClient
	moduleMap  map[string]int
}

func defaultEnv() environment {
	return environment{}
}

func (e *environment) ReportRepo(ctx context.Context) (*git.Repository, error) {
	if v := e.reportRepo; v != nil {
		return v, nil
	}

	return gitrepo.Open(ctx, *reportRepo)
}

func (e *environment) ReportFS() fs.FS {
	if v := e.reportFS; v != nil {
		return v
	}

	return os.DirFS(*reportRepo)
}

func (e *environment) ProxyClient() *proxy.Client {
	if v := e.pc; v != nil {
		return v
	}

	return proxy.NewDefaultClient()
}

func (e *environment) WFS() wfs {
	if v := e.wfs; v != nil {
		return v
	}

	return defaultWFS{}
}

func (e *environment) IssueClient(ctx context.Context) (issueClient, error) {
	if e.ic != nil {
		return e.ic, nil
	}

	if *githubToken == "" {
		return nil, fmt.Errorf("githubToken must be provided")
	}
	owner, repoName, err := gitrepo.ParseGitHubRepo(*issueRepo)
	if err != nil {
		return nil, err
	}
	return issues.NewClient(ctx, &issues.Config{Owner: owner, Repo: repoName, Token: *githubToken}), nil
}

func (e *environment) GHSAClient(ctx context.Context) (ghsaClient, error) {
	if v := e.gc; v != nil {
		return v, nil
	}

	if *githubToken == "" {
		return nil, fmt.Errorf("githubToken must be provided")
	}
	return ghsa.NewClient(ctx, *githubToken), nil
}

func (e *environment) ModuleMap() (map[string]int, error) {
	if v := e.moduleMap; v != nil {
		return v, nil
	}

	return priority.LoadModuleMap()
}
