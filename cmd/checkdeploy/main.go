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

	if err := db.ValidateDeploy(*newPath, *existingPath); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ok to deploy v1 database %s on top of %s\n", *newPath, *existingPath)
}
