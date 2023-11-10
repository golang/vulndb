// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command checkdb validates Go vulnerability databases.
package main

import (
	"flag"
	"fmt"
	"log"

	db "golang.org/x/vulndb/internal/database"
	"golang.org/x/vulndb/internal/database/legacydb"
)

var (
	v1     = flag.Bool("v1", true, "if true, check with respect to v1 database schema")
	legacy = flag.Bool("legacy", false, "if true, check with respect to legacy database schema")
)

func main() {
	flag.Parse()
	path := flag.Arg(0)
	if path == "" {
		log.Fatal("path must be set\nusage: checkdb [path]")
	}
	if !*v1 && !*legacy {
		log.Fatal("no versions set (use flags -v1 and/or -legacy)")
	}
	if *v1 {
		if _, err := db.Load(path); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s contains valid v1 database\n", path)
	} else {
		fmt.Println("skipping v1 validity check (use flag -v1 to enable)")
	}

	if *legacy {
		if _, err := legacydb.Load(path); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s contains valid legacy database\n", path)
	} else {
		fmt.Println("skipping legacy validity check (use flag -legacy to enable)")
	}
}
