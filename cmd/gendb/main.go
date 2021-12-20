// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command gendb provides a tool for converting YAML reports into JSON
// database.
package main

import (
	"flag"
	"log"

	"golang.org/x/vulndb/internal/database"
)

var (
	yamlDir = flag.String("reports", "reports", "Directory containing yaml reports")
	jsonDir = flag.String("out", "out", "Directory to write JSON database to")
)

func main() {
	flag.Parse()
	if err := database.Generate(*yamlDir, *jsonDir); err != nil {
		log.Fatal(err)
	}
}
