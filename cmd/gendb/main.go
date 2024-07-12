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
	"golang.org/x/vulndb/internal/gitrepo"
)

var (
	repoDir = flag.String("repo", ".", "Directory containing vulndb repo")
	jsonDir = flag.String("out", "out", "Directory to write JSON database to")
	zipFile = flag.String("zip", "", "if provided, file to write zipped database to (for v1 database only)")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	repo, err := gitrepo.CloneOrOpen(ctx, *repoDir)
	if err != nil {
		log.Fatal(err)
	}
	d, err := db.FromRepo(ctx, repo)
	if err != nil {
		log.Fatal(err)
	}
	if err := d.Write(*jsonDir); err != nil {
		log.Fatal(err)
	}
	if *zipFile != "" {
		if err := d.WriteZip(*zipFile); err != nil {
			log.Fatal(err)
		}
	}
}
