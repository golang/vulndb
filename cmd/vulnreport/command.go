// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	// setup populates any state needed to run the subcommand.
	setup(context.Context) error
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
func run(ctx context.Context, c command, args []string) (err error) {
	if err := c.setup(ctx); err != nil {
		return err
	}

	stats := &counter{}
	defer func() {
		if cerr := c.close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		log.Infof("%s: processed %d %s(s) (success=%d; skip=%d; error=%d)", c.name(), stats.total(), c.inputType(), stats.succeeded, stats.skipped, stats.errored)
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
	setup(context.Context) error
}

func setupAll(ctx context.Context, fs ...setuper) error {
	for _, f := range fs {
		if err := f.setup(ctx); err != nil {
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
type filenameParser bool

func (filenameParser) inputType() string {
	return "report"
}

func (filenameParser) parseArgs(_ context.Context, args []string) (filenames []string, _ error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}
	for _, arg := range args {
		fname, err := argToFilename(arg)
		if err != nil {
			log.Err(err)
			continue
		}
		filenames = append(filenames, fname)
	}
	return filenames, nil
}

func argToFilename(arg string) (string, error) {
	if _, err := os.Stat(arg); err != nil {
		// If arg isn't a file, see if it might be an issue ID
		// with an existing report.
		for _, padding := range []string{"", "0", "00", "000"} {
			m, _ := filepath.Glob("data/*/GO-*-" + padding + arg + ".yaml")
			if len(m) == 1 {
				return m[0], nil
			}
		}
		return "", fmt.Errorf("%s is not a valid filename or issue ID with existing report: %w", arg, err)
	}
	return arg, nil
}

func (filenameParser) lookup(_ context.Context, filename string) (any, error) {
	r, err := report.ReadStrict(filename)
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
