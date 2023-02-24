// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command checkdeploy validates that it is safe to deploy a new
// vulnerability database in the legacy format.
package main

import (
	"flag"
	"log"

	"golang.org/x/vulndb/internal/database/legacydb"
)

var (
	newPath      = flag.String("new", "", "path to new database")
	existingPath = flag.String("existing", "", "path to existing database")
)

func main() {
	flag.Parse()
	if *newPath == "" {
		log.Fatalf("flag -new must be set")
	}
	if *existingPath == "" {
		log.Fatalf("flag -existing must be set")
	}
	if err := legacydb.Validate(*newPath, *existingPath); err != nil {
		log.Fatal(err)
	}
}
