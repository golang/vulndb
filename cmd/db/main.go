// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command db provides a tool for creating and checking the vulndb.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/vulndb/internal/database"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: db [cmd]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  diff [dbname1] [dbname2]: compare two different versions of the vulndb\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  generate [reportsDir] [jsonDir]: create a new vulndb\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 3 {
		flag.Usage()
		os.Exit(1)
	}
	cmd := os.Args[0]
	switch cmd {
	case "diff":
		if err := database.Diff(os.Args[1], os.Args[2]); err != nil {
			log.Fatal(err)
		}
	case "generate":
		if err := database.Generate(os.Args[1], os.Args[2]); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported command: %q", cmd)
	}
}
