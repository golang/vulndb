// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Populate the firestore DB with commit times.
// This is a one-time update to backfill data.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/vulndb/internal/gitrepo"
	"google.golang.org/api/iterator"
)

var (
	project       = flag.String("project", "", "project ID (required)")
	namespace     = flag.String("namespace", "", "Firestore namespace (required)")
	localRepoPath = flag.String("local-cve-repo", "", "path to local repo")
	startAfter    = flag.String("start", "", "CVE ID to start after")
	limit         = flag.Int("limit", 0, "max to process")
)

const (
	namespaceCollection = "Namespaces"
	cveCollection       = "CVEs"
)

func main() {
	flag.Parse()
	if *project == "" {
		log.Fatal("need -project")
	}
	if *namespace == "" {
		log.Fatal("need -namespace")
	}
	if *localRepoPath == "" {
		log.Fatal("need local-cve-repo")
	}
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	client, err := firestore.NewClient(ctx, *project)
	if err != nil {
		return err
	}
	defer client.Close()
	repo, err := gitrepo.Open(ctx, *localRepoPath)
	if err != nil {
		return err
	}
	nsDoc := client.Collection(namespaceCollection).Doc(*namespace)

	commitTimeCache := map[string]time.Time{}

	getCommitTime := func(hash string) (time.Time, error) {
		if t, ok := commitTimeCache[hash]; ok {
			return t, nil
		}
		commit, err := repo.CommitObject(plumbing.NewHash(hash))
		if err != nil {
			return time.Time{}, err
		}
		ct := commit.Committer.When.In(time.UTC)
		fmt.Printf("commit %s at %s\n", hash, ct)
		commitTimeCache[hash] = ct
		return ct, nil
	}

	q := nsDoc.Collection(cveCollection).Query
	if *startAfter != "" {
		q = q.OrderBy(firestore.DocumentID, firestore.Asc).StartAfter(*startAfter)
	}
	if *limit != 0 {
		q = q.Limit(*limit)
	}
	iter := q.Documents(ctx)
	defer iter.Stop()
	n := 0
	lastID, err := updateDB(ctx, client, iter, func(ds *firestore.DocumentSnapshot, wb *firestore.WriteBatch) (bool, error) {
		n++
		if n%100 == 0 {
			fmt.Println("record #", n)
		}
		_, err := ds.DataAt("CommitTime")
		if err != nil && strings.Contains(err.Error(), "no field") {
			ch, err := ds.DataAt("CommitHash")
			if err != nil {
				return false, err
			}
			ct, err := getCommitTime(ch.(string))
			if err != nil {
				return false, err
			}
			wb.Update(ds.Ref, []firestore.Update{{Path: "CommitTime", Value: ct}})
			return true, nil
		} else {
			return false, err
		}
	})
	if err != nil {
		return err
	}
	fmt.Printf("last ID = %s\n", lastID)
	return nil
}

const maxBatchSize = 500

func updateDB(ctx context.Context, client *firestore.Client, iter *firestore.DocumentIterator, update func(*firestore.DocumentSnapshot, *firestore.WriteBatch) (bool, error)) (string, error) {
	done := false
	var lastID string
	for !done {
		fmt.Println("start batch")
		wb := client.Batch()
		size := 0
		for {
			ds, err := iter.Next()
			if err == iterator.Done {
				done = true
				break
			}
			if err != nil {
				return "", err
			}
			lastID = ds.Ref.ID
			if b, err := update(ds, wb); err != nil {
				return "", err
			} else if b {
				size++
				if size >= maxBatchSize {
					break
				}
			}
		}
		if size > 0 {
			fmt.Printf("committing %d writes\n", size)
			_, err := wb.Commit(ctx)
			if err != nil {
				return "", err
			}
		}
	}
	return lastID, nil
}
