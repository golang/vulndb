// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command gendb provides a tool for converting YAML reports into JSON
// Go vulnerability databases.
package main

import (
	"context"
	"flag"
	"log"

	db "golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/database/legacydb"
	"golang.org/x/vulndb/internal/gitrepo"
)

var (
	repoDir = flag.String("repo", ".", "Directory containing vulndb repo")
	jsonDir = flag.String("out", "out", "Directory to write JSON database to")
	indent  = flag.Bool("indent", false, "Indent JSON for debugging")
	legacy  = flag.Bool("legacy", false, "if true, generate in the legacy schema")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	repo, err := gitrepo.CloneOrOpen(ctx, *repoDir)
	if err != nil {
		log.Fatal(err)
	}
	if *legacy {
		if err := legacydb.Generate(ctx, repo, *jsonDir, *indent); err != nil {
			log.Fatal(err)
		}
	} else {
		d, err := db.FromRepo(ctx, repo)
		if err != nil {
			log.Fatal(err)
		}
		if err := d.Write(*jsonDir); err != nil {
			log.Fatal(err)
		}
	}
}
