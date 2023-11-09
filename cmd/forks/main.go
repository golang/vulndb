// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command forks determines if Go modules are similar.
package main

import (
	"context"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"
)

func main() {
	flag.Parse()
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

type ForksDB struct {
	Comment   string
	Timestamp time.Time
	// Mapping from int to module@version
	Modules []string
	// Equivalence classes
	Classes [][]int
}

func run(ctx context.Context) error {
	dbFilename := os.Getenv("FORKSDB")
	if dbFilename == "" {
		return errors.New("must set FORKSDB to file")
	}
	f, err := os.Open(dbFilename)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	var db ForksDB
	if err := dec.Decode(&db); err != nil {
		return err
	}

	// Build a map from module@version to equivalence class.
	moduleToClass := map[string][]int{}
	for _, c := range db.Classes {
		for _, id := range c {
			moduleToClass[db.Modules[id]] = c
		}
	}

	// Build a map from a module path to all its versions.
	pathToVersions := map[string][]string{}
	for _, mv := range db.Modules {
		path, version, found := strings.Cut(mv, "@")
		if !found {
			return fmt.Errorf("bad module@version: %q", mv)
		}
		pathToVersions[path] = append(pathToVersions[path], version)
	}

	printForks := func(mv string) {
		c := moduleToClass[mv]
		if c == nil {
			fmt.Printf("%s: no forks\n", mv)
		} else {
			fmt.Printf("%s:\n", mv)
			for _, id := range c {
				mv2 := db.Modules[id]
				if mv2 != mv {
					fmt.Printf("    %s\n", mv2)
				}
			}
			fmt.Println()
		}
	}

	for _, arg := range flag.Args() {
		if strings.ContainsRune(arg, '@') {
			printForks(arg)
		} else { // treat arg as a module path
			versions := pathToVersions[arg]
			if len(versions) == 0 {
				fmt.Printf("%s is not a known module path\n", arg)
			} else {
				for _, v := range versions {
					printForks(arg + "@" + v)
				}
			}
		}
	}
	return nil
}
