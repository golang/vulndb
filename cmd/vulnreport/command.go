// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/report"
)

// command represents a subcommand of vulnreport.
type command interface {
	// name outputs the string used to invoke the subcommand.
	name() string
	// usage outputs strings indicating how to use the subcommand.
	usage() (args string, desc string)
	setuper
	// parseArgs takes in the raw args passed to the command line,
	// and converts them to a representation understood by "run".
	// This function need not be one-to-one: there may be more
	// inputs than args or vice-versa.
	parseArgs(_ context.Context, args []string) (inputs []string, _ error)
	lookup(context.Context, string) (any, error)
	skip(any) string
	run(context.Context, any) error
	// close cleans up state and/or completes tasks that should occur
	// after run is called on all inputs.
	close() error
	inputType() string
}

// run executes the given command on the given raw arguments.
func run(ctx context.Context, c command, args []string, env environment) (err error) {
	if err := c.setup(ctx, env); err != nil {
		return err
	}

	stats := &counter{}
	defer func() {
		if cerr := c.close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		if total := stats.total(); total > 0 {
			log.Infof("%s: processed %d %s(s) (success=%d; skip=%d; error=%d)", c.name(), total, c.inputType(), stats.succeeded, stats.skipped, stats.errored)
		}
		if stats.errored > 0 {
			err = errors.Join(err, fmt.Errorf("errored on %d inputs", stats.errored))
		}
	}()

	inputs, err := c.parseArgs(ctx, args)
	if err != nil {
		return err
	}

	log.Infof("%s: operating on %d %s(s)", c.name(), len(inputs), c.inputType())

	for _, input := range inputs {
		in, err := c.lookup(ctx, input)
		if err != nil {
			stats.errored++
			log.Errf("%s: lookup %s failed: %s", c.name(), input, err)
			continue
		}

		if reason := c.skip(in); reason != "" {
			stats.skipped++
			log.Infof("%s: skipping %s (%s)", c.name(), toString(in), reason)
			continue
		}

		log.Infof("%s %s", c.name(), input)
		if err := c.run(ctx, in); err != nil {
			stats.errored++
			log.Errf("%s: %s", c.name(), err)
			continue
		}
		stats.succeeded++
	}

	return nil
}

type counter struct {
	skipped   int
	succeeded int
	errored   int
}

func (c *counter) total() int {
	return c.skipped + c.succeeded + c.errored
}

func toString(in any) string {
	switch v := in.(type) {
	case *yamlReport:
		return fmt.Sprintf("report %s", v.Report.ID)
	case *issues.Issue:
		return fmt.Sprintf("issue #%d", v.Number)
	default:
		return fmt.Sprintf("%v", v)
	}
}

type setuper interface {
	// setup populates state needed to run a command.
	setup(context.Context, environment) error
}

func setupAll(ctx context.Context, env environment, fs ...setuper) error {
	for _, f := range fs {
		if err := f.setup(ctx, env); err != nil {
			return err
		}
	}
	return nil
}

type closer interface {
	close() error
}

func closeAll(cs ...closer) error {
	for _, c := range cs {
		if err := c.close(); err != nil {
			return err
		}
	}
	return nil
}

const (
	filenameArgs = "[filename | github-id] ..."
	ghIssueArgs  = "[github-id] ..."
)

// filenameParser implements the "parseArgs" function of the command
// interface, and can be used by commands that operate on YAML filenames.
type filenameParser struct {
	fsys fs.FS
}

func (f *filenameParser) setup(_ context.Context, env environment) error {
	f.fsys = env.ReportFS()
	return nil
}

func (*filenameParser) inputType() string {
	return "report"
}

func (f *filenameParser) parseArgs(_ context.Context, args []string) (filenames []string, allErrs error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}
	for _, arg := range args {
		fname, err := argToFilename(arg, f.fsys)
		if err != nil {
			log.Err(err)
			continue
		}
		filenames = append(filenames, fname)
	}

	if len(filenames) == 0 {
		return nil, fmt.Errorf("could not parse any valid filenames from arguments")
	}

	return filenames, nil
}

func argToFilename(arg string, fsys fs.FS) (string, error) {
	if _, err := fs.Stat(fsys, arg); err != nil {
		// If arg isn't a file, see if it might be an issue ID
		// with an existing report.
		for _, padding := range []string{"", "0", "00", "000"} {
			m, _ := fs.Glob(fsys, "data/*/GO-*-"+padding+arg+".yaml")
			if len(m) == 1 {
				return m[0], nil
			}
		}
		return "", fmt.Errorf("could not parse argument %q: not a valid filename or issue ID with existing report: %w", arg, err)
	}
	return arg, nil
}

func (f *filenameParser) lookup(_ context.Context, filename string) (any, error) {
	r, err := report.ReadStrict(f.fsys, filename)
	if err != nil {
		return nil, err
	}
	return &yamlReport{Report: r, Filename: filename}, nil
}

type noSkip bool

func (noSkip) skip(any) string {
	return ""
}

type yamlReport struct {
	*report.Report
	Filename string
}
