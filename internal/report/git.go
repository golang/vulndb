// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"os"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
)

// expandGitCommits expands git repositories and names to commits.
// Expands versions in r of the form <url>@<name> where url starts with
// one of {'git://', 'https://', 'http://', 'ssh://', 'git+ssh://'}
// and name is the name of a git branch or git tag to a git commit
// hash. Any version that is successfully expanded is replaced.
func expandGitCommits(r *Report) {
	// Find repos in versions to expand
	repos := make(map[string][]string) // url -> names
	perVersion := func(v string) {
		if b, a, f := cutRepoUrl(v); f {
			repos[b] = append(repos[b], a)
		}
	}
	for _, m := range r.Modules {
		for _, vr := range m.Versions {
			perVersion(vr.Introduced)
			perVersion(vr.Fixed)
		}
		perVersion(m.VulnerableAt)
	}

	if len(repos) == 0 { // no repos to expand
		return
	}

	log.Infof("Expanding git urls for %d repos", len(repos))

	// Create scratch directory.
	scratch, err := os.MkdirTemp("", "expand-git-references")
	if err != nil {
		log.Err("failed to create scratch directory for ExpandGitReferences")
		return
	}
	defer func() {
		_ = os.RemoveAll(scratch)
	}()

	// expand references and compute replacements
	replacements := make(map[string]string)
	for repo, names := range repos {
		commits, err := gitNameToCommits(scratch, repo, names)
		if err != nil {
			log.Infof("expandGitCommits(%v, %v) failed with: %v", repo, names, err)
			continue
		}
		for name, c := range commits {
			replacements[repo+"@"+name] = c
		}
	}

	if len(replacements) == 0 { // no replacements created
		return
	}

	// Replace all.
	replaceVersion := func(v string) string {
		if r, ok := replacements[v]; ok {
			return r
		}
		return v
	}
	for i, m := range r.Modules {
		for j, vr := range m.Versions {
			m.Versions[j].Introduced = replaceVersion(vr.Introduced)
			m.Versions[j].Fixed = replaceVersion(vr.Fixed)
		}
		r.Modules[i].VulnerableAt = replaceVersion(m.VulnerableAt)
	}
}

func cutRepoUrl(v string) (string, string, bool) {
	prefixes := map[string]bool{
		"https://":   true,
		"http://":    true,
		"git://":     true,
		"git+ssh://": true,
		"ssh://":     true,
	}
	for p := range prefixes {
		if strings.HasPrefix(v, p) {
			return strings.Cut(v, "@")
		}
	}
	return v, "", false
}

// gitNameToCommits returns a mapping from the git repo at repoURL
// and returns a mapping for the branches and tags in names to
// a commit hash.
func gitNameToCommits(dir string, repoURL string, names []string) (_ map[string]string, err error) {
	defer derrors.Wrap(&err, "gitNameToCommits(%q, %q, %v)", dir, repoURL, names)

	repoRoot, err := os.MkdirTemp(dir, "git*")
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	repo, err := gitrepo.PlainCloneWith(ctx, repoRoot, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.HEAD,
		SingleBranch:  true, // allow branches other than master
		Depth:         0,    // pull in history
		// Leaves Tags the default value.
	})
	if err != nil {
		return nil, err
	}

	resolveName := func(name string) (string, bool) {
		// branch name?
		if b, err := repo.Branch(name); err == nil {
			if ref, err := repo.Reference(b.Merge, true); err == nil {
				if h := ref.Hash(); !h.IsZero() {
					return h.String(), true
				}
			}
		}

		// tag name?
		if ref, err := repo.Tag(name); err == nil {
			if h := ref.Hash(); !h.IsZero() {
				return h.String(), true
			}
		}

		return "", false
	}

	results := make(map[string]string)
	for _, name := range names {
		if r, ok := resolveName(name); ok {
			results[name] = r
		}
	}
	return results, nil
}
