// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command checkdb validates Go vulnerability databases.
package main

import (
	"flag"
	"log"

	"golang.org/x/vulndb/internal/database"
)

func main() {
	flag.Parse()
	path := flag.Arg(0)
	if path == "" {
		log.Fatal("path must be set\nusage: checkdb [path]")
	}
	if _, err := database.Load(path); err != nil {
		log.Fatal(err)
	}
}
