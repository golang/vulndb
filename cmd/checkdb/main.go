// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command checkdb validates Go vulnerability databases.
package main

import (
	"flag"
	"log"

	db "golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/database/legacydb"
)

var legacy = flag.Bool("legacy", false, "if true, check with respect to legacy database schema")

func main() {
	flag.Parse()
	path := flag.Arg(0)
	if path == "" {
		log.Fatal("path must be set\nusage: checkdb [path]")
	}
	if *legacy {
		if _, err := legacydb.Load(path); err != nil {
			log.Fatal(err)
		}
	} else {
		if _, err := db.Load(path); err != nil {
			log.Fatal(err)
		}
	}
}
