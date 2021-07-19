// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/vulndb/report"
	"gopkg.in/yaml.v2"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "only expect a single argument")
		os.Exit(1)
	}

	content, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to read %q: %s\n", os.Args[1], err)
		os.Exit(1)
	}

	var vuln report.Report
	err = yaml.UnmarshalStrict(content, &vuln)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to parse %q: %s\n", os.Args[1], err)
		os.Exit(1)
	}

	if err = vuln.Lint(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid vulnerability file %q: %s\n", os.Args[1], err)
		os.Exit(1)
	}
}
