// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/worker/log"
)

// Run clones the CVEProject/cvelist repository and compares the files to the
// existing triaged-cve-list.
func Run(dirpath string, triaged map[string]string) (err error) {
	ctx := context.Background()
	defer derrors.Wrap(&err, "Run(triaged)")
	var repo *git.Repository
	if dirpath != "" {
		repo, err = gitrepo.Open(ctx, dirpath)
	} else {
		repo, err = gitrepo.Clone(ctx, gitrepo.CVEListRepoURL)
	}
	if err != nil {
		return err
	}
	root, err := gitrepo.Root(repo)
	if err != nil {
		return err
	}
	t := newTriager(triaged)
	log.Infof(ctx, "Finding new Go vulnerabilities from CVE list...")
	if err := walkRepo(repo, root, "", t); err != nil {
		return err
	}
	var newVulns []string
	for cveID, r := range t {
		if r.isGoVuln {
			newVulns = append(newVulns, fmt.Sprintf("%s (%s)", cveID, r.modulePath))
		}
	}
	sort.Strings(newVulns)
	log.Infof(context.Background(), "Found %d new issues from %d CVEs", t.totalVulns(), t.totalCVEs())
	for _, v := range newVulns {
		fmt.Println(v)
	}
	return nil
}

// walkRepo looks at the files in t, recursively, and check if it is a CVE that
// needs to be manually triaged.
func walkRepo(repo *git.Repository, root *object.Tree, dirpath string, t triager) (err error) {
	defer derrors.Wrap(&err, "walkRepo(repo, root, %q, t)", dirpath)
	for _, e := range root.Entries {
		fp := path.Join(dirpath, e.Name)
		if !strings.HasPrefix(fp, "202") {
			continue
		}
		switch e.Mode {
		case filemode.Dir:
			root2, err := repo.TreeObject(e.Hash)
			if err != nil {
				return err
			}
			if err := walkRepo(repo, root2, fp, t); err != nil {
				return err
			}
		default:
			if !strings.HasPrefix(e.Name, "CVE-") {
				continue
			}
			cveID := strings.TrimSuffix(e.Name, ".json")
			if t.contains(cveID) {
				continue
			}
			c, err := parseCVE(repo, e)
			if err != nil {
				return err
			}
			issue, err := triageCVE(c)
			if err != nil {
				return err
			}
			if issue != nil {
				t.add(issue)
			}
		}
	}
	return nil
}

// parseCVEJSON parses a CVE file following the CVE JSON format:
// https://github.com/CVEProject/automation-working-group/blob/master/cve_json_schema/DRAFT-JSON-file-format-v4.md
func parseCVE(r *git.Repository, e object.TreeEntry) (_ *cveschema.CVE, err error) {
	defer derrors.Wrap(&err, "parseCVE(r, e)")
	blob, err := r.BlobObject(e.Hash)
	if err != nil {
		return nil, fmt.Errorf("r.BlobObject: %v", err)
	}
	src, err := blob.Reader()
	if err != nil {
		return nil, fmt.Errorf("blob.Reader: %v", err)
	}
	defer func() {
		cerr := src.Close()
		if err == nil {
			err = cerr
		}
	}()
	var c cveschema.CVE
	d := json.NewDecoder(src)
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("d.Decode: %v", err)
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
