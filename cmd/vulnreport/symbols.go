// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"

	"github.com/go-git/go-git/v5"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

var (
	update = flag.Bool("update", false, "for symbols, populate the FixLinks field for each module")
)

type symbolsCmd struct {
	*filenameParser
	*fileWriter
	*repoWalker
	noSkip
}

func (symbolsCmd) name() string { return "symbols" }

func (symbolsCmd) usage() (string, string) {
	const desc = "finds and populates possible vulnerable symbols for a given report"
	return filenameArgs, desc
}

func (s *symbolsCmd) parseArgs(ctx context.Context, args []string) ([]string, error) {
	if len(args) > 0 {
		return s.filenameParser.parseArgs(ctx, args)
	}
	return s.repoWalker.modifiedYAMLFiles()
}

func (s *symbolsCmd) setup(ctx context.Context, env environment) error {
	s.filenameParser = new(filenameParser)
	s.fileWriter = new(fileWriter)
	s.repoWalker = new(repoWalker)
	return setupAll(ctx, env, s.filenameParser, s.fileWriter, s.repoWalker)
}

func (*symbolsCmd) close() error { return nil }

func (s *symbolsCmd) run(ctx context.Context, input any) (err error) {
	r := input.(*yamlReport)

	if err = symbols.Populate(r.Report, *update); err != nil {
		return err
	}

	return s.write(r)
}

type repoWalker struct {
	repo *git.Repository
}

func (rw *repoWalker) setup(ctx context.Context, env environment) (err error) {
	rw.repo, err = env.ReportRepo(ctx)
	return err
}

func (rw *repoWalker) modifiedYAMLFiles() ([]string, error) {
	statusMap, err := gitrepo.WorktreeStatus(rw.repo)
	if err != nil {
		return nil, err
	}

	var filenames []string
	var errs []error
	for fname, status := range statusMap {
		if report.IsYAMLReport(fname) && status.Worktree != git.Deleted {
			r, err := report.Read(fname)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			if r.ReviewStatus == report.NeedsReview || r.ReviewStatus == report.Reviewed {
				filenames = append(filenames, fname)
			}
		}
	}

	return filenames, errors.Join(errs...)
}
