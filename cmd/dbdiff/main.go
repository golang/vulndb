// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command dbdiff provides a tool for comparing two different versions of the
// vulnerability database.
package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/vulndb/internal/database"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: dbdiff db-a db-b")
		os.Exit(1)
	}
	if err := database.Diff(os.Args[1], os.Args[2]); err != nil {
		log.Fatal(err)
	}
}
