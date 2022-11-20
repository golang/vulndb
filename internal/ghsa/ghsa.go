// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ghsa supports GitHub security advisories.
package ghsa

import (
	"context"
	"fmt"
	"time"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// A SecurityAdvisory represents a GitHub security advisory.
type SecurityAdvisory struct {
	// The GitHub Security Advisory identifier.
	ID string
	// A complete list of identifiers, e.g. CVE numbers.
	Identifiers []Identifier
	// A short description of the advisory.
	Summary string
	// A full description of the advisory.
	Description string
	// Where the advisory came from.
	Origin string
	// A link to a page for the advisory.
	Permalink string
	// When the advisory was first published.
	PublishedAt time.Time
	// When the advisory was last updated; should always be >= PublishedAt.
	UpdatedAt time.Time
	// The vulnerabilities associated with this advisory.
	Vulns []*Vuln
}

// An Identifier identifies an advisory according to some scheme or
// organization, given by the Type field. Example types are GHSA and CVE.
type Identifier struct {
	Type  string
	Value string
}

// A Vuln represents a vulnerability.
type Vuln struct {
	// The vulnerable Go package or module.
	Package string
	// The severity of the vulnerability.
	Severity githubv4.SecurityAdvisorySeverity
	// The earliest fixed version.
	EarliestFixedVersion string
	// A string representing the range of vulnerable versions.
	// E.g. ">= 1.0.3"
	VulnerableVersionRange string
	// When the vulnerability was last updated.
	UpdatedAt time.Time
}

// A gqlSecurityAdvisory represents a GitHub security advisory structured for
// GitHub's GraphQL schema. The fields must be exported to be populated by
// Github's Client.Query function.
type gqlSecurityAdvisory struct {
	GhsaID          string
	Identifiers     []Identifier
	Summary         string
	Description     string
	Origin          string
	Permalink       githubv4.URI
	PublishedAt     time.Time
	UpdatedAt       time.Time
	Vulnerabilities struct {
		Nodes []struct {
			Package struct {
				Name      string
				Ecosystem string
			}
			FirstPatchedVersion    struct{ Identifier string }
			Severity               githubv4.SecurityAdvisorySeverity
			UpdatedAt              time.Time
			VulnerableVersionRange string
		}
		PageInfo struct {
			HasNextPage bool
		}
	} `graphql:"vulnerabilities(first: 100, ecosystem: $go)"` // include only Go vulns
}

// securityAdvisory converts a gqlSecurityAdvisory into a SecurityAdvisory.
// Errors if the security advisory was updated before it was published, or if
// there are more than 100 vulnerabilities associated with the advisory.
func (sa *gqlSecurityAdvisory) securityAdvisory() (*SecurityAdvisory, error) {
	if sa.PublishedAt.After(sa.UpdatedAt) {
		return nil, fmt.Errorf("%s: published at %s, after updated at %s", sa.GhsaID, sa.PublishedAt, sa.UpdatedAt)
	}
	if sa.Vulnerabilities.PageInfo.HasNextPage {
		return nil, fmt.Errorf("%s has more than 100 vulns", sa.GhsaID)
	}
	s := &SecurityAdvisory{
		ID:          sa.GhsaID,
		Identifiers: sa.Identifiers,
		Summary:     sa.Summary,
		Description: sa.Description,
		Origin:      sa.Origin,
		Permalink:   sa.Permalink.URL.String(),
		PublishedAt: sa.PublishedAt,
		UpdatedAt:   sa.UpdatedAt,
	}
	for _, v := range sa.Vulnerabilities.Nodes {
		s.Vulns = append(s.Vulns, &Vuln{
			Package:                v.Package.Name,
			Severity:               v.Severity,
			EarliestFixedVersion:   v.FirstPatchedVersion.Identifier,
			VulnerableVersionRange: v.VulnerableVersionRange,
			UpdatedAt:              v.UpdatedAt,
		})
	}
	return s, nil
}

func newGitHubClient(ctx context.Context, accessToken string) *githubv4.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	tc := oauth2.NewClient(ctx, ts)
	return githubv4.NewClient(tc)
}

// List returns all SecurityAdvisories that affect Go,
// published or updated since the given time.
func List(ctx context.Context, accessToken string, since time.Time) ([]*SecurityAdvisory, error) {
	client := newGitHubClient(ctx, accessToken)

	var query struct { // the GraphQL query
		SAs struct {
			Nodes    []gqlSecurityAdvisory
			PageInfo struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
		} `graphql:"securityAdvisories(updatedSince: $since, first: 100, after: $cursor)"`
	}
	vars := map[string]any{
		"cursor": (*githubv4.String)(nil),
		"go":     githubv4.SecurityAdvisoryEcosystemGo,
		"since":  githubv4.DateTime{Time: since},
	}

	var sas []*SecurityAdvisory
	// We need a loop to page through the list. The GitHub API limits us to 100
	// values per call.
	for {
		if err := client.Query(ctx, &query, vars); err != nil {
			return nil, err
		}
		for _, sa := range query.SAs.Nodes {
			if len(sa.Vulnerabilities.Nodes) == 0 {
				continue
			}
			s, err := sa.securityAdvisory()
			if err != nil {
				return nil, err
			}
			sas = append(sas, s)
		}
		if !query.SAs.PageInfo.HasNextPage {
			break
		}
		vars["cursor"] = githubv4.NewString(query.SAs.PageInfo.EndCursor)
	}
	return sas, nil
}

func ListForCVE(ctx context.Context, accessToken string, cve string) ([]*SecurityAdvisory, error) {
	client := newGitHubClient(ctx, accessToken)

	var query struct { // The GraphQL query
		SAs struct {
			Nodes    []gqlSecurityAdvisory
			PageInfo struct {
				EndCursor   githubv4.String
				HasNextPage bool
			}
		} `graphql:"securityAdvisories(identifier: $id, first: 100)"`
	}
	vars := map[string]any{
		"id": githubv4.SecurityAdvisoryIdentifierFilter{
			Type:  githubv4.SecurityAdvisoryIdentifierTypeCve,
			Value: githubv4.String(cve),
		},
		"go": githubv4.SecurityAdvisoryEcosystemGo,
	}

	if err := client.Query(ctx, &query, vars); err != nil {
		return nil, err
	}
	if query.SAs.PageInfo.HasNextPage {
		return nil, fmt.Errorf("CVE %s has more than 100 GHSAs", cve)
	}
	var sas []*SecurityAdvisory
	for _, sa := range query.SAs.Nodes {
		if len(sa.Vulnerabilities.Nodes) == 0 {
			continue
		}
		exactMatch := false
		for _, id := range sa.Identifiers {
			if id.Type == "CVE" && id.Value == cve {
				exactMatch = true
				continue
			}
		}
		if !exactMatch {
			continue
		}

		s, err := sa.securityAdvisory()
		if err != nil {
			return nil, err
		}
		sas = append(sas, s)
	}
	return sas, nil
}

// FetchGHSA returns the SecurityAdvisory for the given Github Security
// Advisory ID.
func FetchGHSA(ctx context.Context, accessToken, ghsaID string) (_ *SecurityAdvisory, err error) {
	client := newGitHubClient(ctx, accessToken)

	var query struct {
		SA gqlSecurityAdvisory `graphql:"securityAdvisory(ghsaId: $id)"`
	}
	vars := map[string]any{
		"id": githubv4.String(ghsaID),
		"go": githubv4.SecurityAdvisoryEcosystemGo,
	}

	if err := client.Query(ctx, &query, vars); err != nil {
		return nil, err
	}

	return query.SA.securityAdvisory()
}
