// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/vulndb/cmd/vulnreport/log"
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
	// run executes the subcommand on the given input.
	run(_ context.Context, input string) error
	// close cleans up state and/or completes tasks that should occur
	// after run is called on all inputs.
	close() error
}

// run executes the given command on the given raw arguments.
func run(ctx context.Context, c command, args []string) error {
	if err := c.setup(ctx); err != nil {
		return err
	}
	defer c.close()

	inputs, err := c.parseArgs(ctx, args)
	if err != nil {
		return err
	}

	for _, input := range inputs {
		log.Infof("%s %v", c.name(), input)
		if err := c.run(ctx, input); err != nil {
			log.Errf("%s: %s", c.name(), err)
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
