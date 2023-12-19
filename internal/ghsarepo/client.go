// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Package ghsarepo provides a client and utilities for reading
// GitHub security advisories directly from the Git repo
// https://github.com/github/advisory-database.
//
// This allows us to read GHSAs in OSV format instead of
// the SecurityAdvisory format output by the GraphQL API.
package ghsarepo

import (
	"encoding/json"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/exp/maps"
	"golang.org/x/vulndb/internal/genericosv"
	"golang.org/x/vulndb/internal/gitrepo"
)

type Client struct {
	byID    map[string]*genericosv.Entry
	byAlias map[string][]*genericosv.Entry
}

// NewClient returns a client to read from the GHSA database.
// It clones the Git repo at https://github.com/github/advisory-database,
// which can take around ~20 seconds.
func NewClient() (*Client, error) {
	repo, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
		URL:           "https://github.com/github/advisory-database",
		ReferenceName: "refs/heads/main",
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
		NoCheckout:    true,
	})
	if err != nil {
		return nil, err
	}
	return NewClientFromRepo(repo)
}

// NewClient returns a client that reads from the GHSA database
// in the given repo, which must follow the structure of
// https://github.com/github/advisory-database.
func NewClientFromRepo(repo *git.Repository) (*Client, error) {
	const reviewed = "advisories/github-reviewed"
	root, err := gitrepo.Root(repo)
	if err != nil {
		return nil, err
	}
	e, err := root.FindEntry(reviewed)
	if err != nil {
		return nil, err
	}
	tree, err := repo.TreeObject(e.Hash)
	if err != nil {
		return nil, err
	}

	c := &Client{
		byID:    make(map[string]*genericosv.Entry),
		byAlias: make(map[string][]*genericosv.Entry),
	}
	if err := tree.Files().ForEach(func(f *object.File) error {
		contents, err := f.Contents()
		if err != nil {
			return err
		}
		var advisory genericosv.Entry
		if err := json.Unmarshal([]byte(contents), &advisory); err != nil {
			return err
		}
		if !affectsGo(&advisory) {
			return nil
		}
		if !advisory.Withdrawn.IsZero() {
			return nil
		}
		c.byID[advisory.ID] = &advisory
		for _, alias := range advisory.Aliases {
			c.byAlias[alias] = append(c.byAlias[alias], &advisory)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return c, nil
}

func affectsGo(osv *genericosv.Entry) bool {
	for _, a := range osv.Affected {
		if a.Package.Ecosystem == genericosv.EcosystemGo {
			return true
		}
	}
	return false
}

// IDs returns all the GHSA IDs in the GHSA database.
func (c *Client) IDs() []string {
	return maps.Keys(c.byID)
}

// List returns all the genericosv.Entry entries in the GHSA database.
func (c *Client) List() []*genericosv.Entry {
	return maps.Values(c.byID)
}

// ByGHSA returns the genericosv.Entry entry for the given GHSA, or nil if none
// exists.
func (c *Client) ByGHSA(ghsa string) *genericosv.Entry {
	return c.byID[ghsa]
}

// ByCVE returns the genericosv.Entry entries for the given CVE, or nil if none
// exist.
func (c *Client) ByCVE(cve string) []*genericosv.Entry {
	return c.byAlias[cve]
}
