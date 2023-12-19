// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.21

// Command forks determines if Go modules are similar.
package main

import (
	"cmp"
	"context"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"
)

func main() {
	out := flag.CommandLine.Output()
	flag.Usage = func() {
		fmt.Fprintf(out, "usage: forks [ PATH | PATH@VERSION ] ...\n")
		fmt.Fprintf(out, "Print potential forks for each module path or module path @ version.\n")
		fmt.Fprintf(out, "Each fork is preceded by its score. Scores range from 0 to 10, with 10 meaning most\n")
		fmt.Fprintf(out, "similar. Only matches with scores of at least 6 are printed.\n")
		fmt.Fprintf(out, "Scores are approximations that are based on partial data (not the full module content),\n")
		fmt.Fprintf(out, "so even a score of 10 does not mean that the modules are identical.\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

type Forks struct {
	Comment   string
	Timestamp time.Time
	MinScore  int             // smallest score that is stored
	Modules   []string        // mapping from int to module@version
	Matches   map[int][]Score // from module ID to matches and their scores

}

type Score struct {
	Module int // index into Forks.Modules
	Score  int // 0 - 10
}

func run(_ context.Context) error {
	if flag.NArg() == 0 {
		flag.Usage()
		return nil
	}
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
	var db Forks
	if err := dec.Decode(&db); err != nil {
		return err
	}

	// Build a map from path@version and path to ID.
	modsToIDs := buildIndex(db.Modules)

	// Print the forks for each arg.
	for _, arg := range flag.Args() {
		if ids, ok := modsToIDs[arg]; ok {
			for _, id := range ids {
				fmt.Printf("%s\n", db.Modules[id])
				matches := db.Matches[id]
				slices.SortFunc(matches, func(s1, s2 Score) int {
					if c := cmp.Compare(s1.Score, s2.Score); c != 0 {
						return c
					}
					return cmp.Compare(db.Modules[s1.Module], db.Modules[s2.Module])
				})
				for _, m := range matches {
					fmt.Printf("    %2d  %s\n", m.Score, db.Modules[m.Module])
				}
			}
		} else {
			fmt.Printf("%s: no forks\n", arg)
		}
	}
	return nil
}

// buildIndex builds a map from "path@version" and "path" to IDs.
func buildIndex(mods []string) map[string][]int {
	modsToIDs := map[string][]int{}
	for i, mv := range mods {
		path, _, found := strings.Cut(mv, "@")
		if !found {
			panic(fmt.Errorf("no '@' in %s", mv))
		}
		modsToIDs[mv] = append(modsToIDs[mv], i)
		modsToIDs[path] = append(modsToIDs[path], i)
	}
	return modsToIDs
}
