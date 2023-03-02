// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command indexdb provides a tool for creating a v1 vulnerability
// database from a folder containing OSV JSON files.
package main

import (
	"flag"
	"log"

	"golang.org/x/vulndb/internal/database"
)

var (
	vulnsDir = flag.String("vulns", "", "Directory containing JSON OSV files")
	outDir   = flag.String("out", "", "Directory to write database to")
)

func main() {
	flag.Parse()
	if *vulnsDir == "" {
		log.Fatal("flag -vulns must be set")
	}
	if *outDir == "" {
		log.Fatal("flag -out must be set")
	}
	db, err := database.RawLoad(*vulnsDir)
	if err != nil {
		log.Fatal(err)
	}
	if err = db.Write(*outDir); err != nil {
		log.Fatal(err)
	}
}
