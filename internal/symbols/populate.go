// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package symbols

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/report"
)

// repository represents a repository that may contain fixes for a given report.
type repository struct {
	repo      *git.Repository
	url       string
	root      string
	fixHashes []string
}

// Populate attempts to populate the report with symbols derived
// from the patch link(s) in the report.
func Populate(r *report.Report, update bool) error {
	return populate(r, update, gitrepo.PlainClone, Patched)
}

func populate(r *report.Report, update bool, clone func(context.Context, string, string) (*git.Repository, error), patched func(string, string, *repository) (map[string][]string, error)) error {
	commits := r.CommitLinks()
	reportFixRepos, errs := getFixRepos(commits, clone)
	for _, mod := range r.Modules {
		hasFixLinks := len(mod.FixLinks) > 0
		fixRepos := reportFixRepos
		if hasFixLinks {
			frs, ers := getFixRepos(mod.FixLinks, clone)
			if len(ers) != 0 {
				errs = append(errs, ers...)
			}
			fixRepos = frs
		} else if len(commits) == 0 {
			errs = append(errs, fmt.Errorf("no commits found for %s", mod.Module))
			continue
		}

		if len(fixRepos) == 0 {
			errs = append(errs, fmt.Errorf("no working repos found for %s", mod.Module))
			continue
		}

		foundSymbols := false
		for _, repo := range fixRepos {
			for _, hash := range repo.fixHashes {
				found, err := populateFromFixHash(repo, hash, mod, patched)
				if err != nil {
					errs = append(errs, err)
				}
				if !hasFixLinks && update && found {
					fixLink := fmt.Sprintf("%s/commit/%s", repo.url, hash)
					mod.FixLinks = append(mod.FixLinks, fixLink)
				}
				foundSymbols = foundSymbols || found
			}
			root := repo.root
			defer func() {
				_ = os.RemoveAll(root)
			}()
		}

		if !foundSymbols {
			errs = append(errs, fmt.Errorf("no vulnerable symbols found for module %s", mod.Module))
		}
		// Sort fix links for testing/deterministic output
		if !hasFixLinks && update {
			slices.Sort(mod.FixLinks)
		}
	}

	return errors.Join(errs...)
}

// populateFromFixHash takes a repository, fix hash and corresponding module and returns true
// if any symbols are found for the given fix/module pairs.
func populateFromFixHash(repo *repository, fixHash string, m *report.Module, patched func(string, string, *repository) (map[string][]string, error)) (foundSymbols bool, err error) {
	pkgsToSymbols, err := patched(m.Module, fixHash, repo)
	if err != nil {
		return false, err
	}
	modPkgs := m.AllPackages()
	for pkg, symbols := range pkgsToSymbols {
		foundSymbols = true
		if modPkg, exists := modPkgs[pkg]; exists {
			// Ensure there are no duplicate symbols
			for _, s := range symbols {
				if !slices.Contains(modPkg.Symbols, s) {
					modPkg.Symbols = append(modPkg.Symbols, s)
				}
			}
		} else {
			m.Packages = append(m.Packages, &report.Package{
				Package: pkg,
				Symbols: symbols,
			})
		}
	}
	return foundSymbols, nil
}

// getFixRepos takes a list of fix links and returns the repositories and hashes of those fix links.
func getFixRepos(links []string, clone func(context.Context, string, string) (*git.Repository, error)) (fixRepos map[string]*repository, errs []error) {
	fixRepos = make(map[string]*repository)
	for _, fixLink := range links {
		fixHash := filepath.Base(fixLink)
		repoURL := strings.TrimSuffix(fixLink, "/commit/"+fixHash)
		if _, found := fixRepos[repoURL]; !found {
			repoRoot, err := os.MkdirTemp("", fixHash)
			if err != nil {
				errs = append(errs, fmt.Errorf("error making temp dir for repo %s: %v", repoURL, err))
				continue
			}
			ctx := context.Background()
			r, err := clone(ctx, repoRoot, repoURL)
			if err != nil {
				errs = append(errs, fmt.Errorf("error cloning repo: %v", err.Error()))
				continue
			}
			fixRepos[repoURL] = &repository{
				repo:      r,
				url:       repoURL,
				root:      repoRoot,
				fixHashes: []string{fixHash},
			}
		} else {
			r := fixRepos[repoURL]
			r.fixHashes = append(r.fixHashes, fixHash)
		}
	}
	return fixRepos, errs
}
