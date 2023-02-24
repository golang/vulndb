// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command gendb provides a tool for converting YAML reports into JSON
// Go vulnerability databases in the legacy format.
package main

import (
	"context"
	"flag"
	"log"

	"golang.org/x/vulndb/internal/database/legacydb"
	"golang.org/x/vulndb/internal/gitrepo"
)

var (
	repoDir = flag.String("repo", ".", "Directory containing vulndb repo")
	jsonDir = flag.String("out", "out", "Directory to write JSON database to")
	indent  = flag.Bool("indent", false, "Indent JSON for debugging")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	repo, err := gitrepo.CloneOrOpen(ctx, *repoDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := legacydb.Generate(ctx, repo, *jsonDir, *indent); err != nil {
		log.Fatal(err)
	}
}
