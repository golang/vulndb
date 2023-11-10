// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command checkdeploy validates that it is safe to deploy a new
// vulnerability database.
package main

import (
	"flag"
	"fmt"
	"log"

	db "golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/database/legacydb"
)

var (
	newPath       = flag.String("new", "", "path to new database")
	newLegacyPath = flag.String("legacy", "", "path to the new database in the legacy schema (optional)")
	existingPath  = flag.String("existing", "", "path to existing database")
)

func main() {
	flag.Parse()
	if *newPath == "" {
		log.Fatalf("flag -new must be set")
	}
	if *existingPath == "" {
		log.Fatalf("flag -existing must be set")
	}

	if err := db.ValidateDeploy(*newPath, *existingPath); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ok to deploy v1 database %s on top of %s\n", *newPath, *existingPath)

	if *newLegacyPath != "" {
		if err := legacydb.Validate(*newLegacyPath, *existingPath); err != nil {
			log.Fatal(err)
		}
		if err := legacydb.Equivalent(*newPath, *newLegacyPath); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("ok to deploy legacy database %s on top of %s\n", *newLegacyPath, *existingPath)
	} else {
		fmt.Println("not checking legacy database deploy (use -legacy flag to set)")
	}
}
