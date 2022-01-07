// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cveschema"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testStore(t *testing.T, s Store) {
	t.Run("Updates", func(t *testing.T) {
		testUpdates(t, s)
	})
	t.Run("CVEs", func(t *testing.T) {
		testCVEs(t, s)
	})
	t.Run("DirHashes", func(t *testing.T) {
		testDirHashes(t, s)
	})
}

func testUpdates(t *testing.T, s Store) {
	ctx := context.Background()
	start := time.Date(2021, time.September, 1, 0, 0, 0, 0, time.Local)

	u1 := &CommitUpdateRecord{
		StartedAt:  start,
		CommitHash: "abc",
		NumTotal:   100,
	}
	must(t, s.CreateCommitUpdateRecord(ctx, u1))
	u1.EndedAt = u1.StartedAt.Add(10 * time.Minute)
	u1.NumAdded = 100
	must(t, s.SetCommitUpdateRecord(ctx, u1))
	u2 := &CommitUpdateRecord{
		StartedAt:  start.Add(time.Hour),
		CommitHash: "def",
		NumTotal:   80,
	}
	must(t, s.CreateCommitUpdateRecord(ctx, u2))
	u2.EndedAt = u2.StartedAt.Add(8 * time.Minute)
	u2.NumAdded = 40
	u2.NumModified = 40
	must(t, s.SetCommitUpdateRecord(ctx, u2))
	got, err := s.ListCommitUpdateRecords(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []*CommitUpdateRecord{u2, u1}
	diff(t, want, got, cmpopts.IgnoreFields(CommitUpdateRecord{}, "UpdatedAt"))
	for _, g := range got {
		if g.UpdatedAt.IsZero() {
			t.Error("zero UpdatedAt field")
		}
	}
}

func testCVEs(t *testing.T, s Store) {
	ctx := context.Background()
	const (
		id1 = "CVE-1905-0001"
		id2 = "CVE-1905-0002"
		id3 = "CVE-1905-0003"
	)

	date := func(year, month, day int) time.Time {
		return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	}

	crs := []*CVERecord{
		{
			ID:          id1,
			Path:        "1905/" + id1 + ".json",
			BlobHash:    "123",
			CommitHash:  "456",
			CommitTime:  date(2000, 1, 2),
			CVEState:    "PUBLIC",
			TriageState: TriageStateNeedsIssue,
		},
		{
			ID:          id2,
			Path:        "1906/" + id2 + ".json",
			BlobHash:    "abc",
			CommitHash:  "def",
			CommitTime:  date(2001, 3, 4),
			CVEState:    "RESERVED",
			TriageState: TriageStateNoActionNeeded,
		},
		{
			ID:          id3,
			Path:        "1907/" + id3 + ".json",
			BlobHash:    "xyz",
			CommitHash:  "456",
			CommitTime:  date(2010, 1, 2),
			CVEState:    "REJECT",
			TriageState: TriageStateNoActionNeeded,
		},
	}

	getCVERecords := func(startID, endID string) []*CVERecord {
		var got []*CVERecord
		err := s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
			var err error
			got, err = tx.GetCVERecords(startID, endID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	createCVERecords(t, ctx, s, crs)

	diff(t, crs[:1], getCVERecords(id1, id1))
	diff(t, crs[1:], getCVERecords(id2, id3))

	// Test SetCVERecord.

	set := func(r *CVERecord) *CVERecord {
		err := s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
			return tx.SetCVERecord(r)
		})
		if err != nil {
			t.Fatal(err)
		}
		r2, err := s.GetCVERecord(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return r2
	}

	// Make sure the first record is the same that we created.
	got, err := s.GetCVERecord(ctx, id1)
	if err != nil {
		t.Fatal(err)
	}
	diff(t, crs[0], got)

	// Change the state and the commit hash.
	got.CVEState = cveschema.StateRejected
	got.CommitHash = "999"
	set(got)
	want := *crs[0]
	want.CVEState = cveschema.StateRejected
	want.CommitHash = "999"
	diff(t, &want, got)

	gotNoAction, err := s.ListCVERecordsWithTriageState(ctx, TriageStateNoActionNeeded)
	if err != nil {
		t.Fatal(err)
	}
	diff(t, crs[1:], gotNoAction)
}

func testDirHashes(t *testing.T, s Store) {
	ctx := context.Background()
	const dir = "a/b/c"
	got, err := s.GetDirectoryHash(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	const want = "123"
	if err := s.SetDirectoryHash(ctx, "a/b/c", want); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetDirectoryHash(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func createCVERecords(t *testing.T, ctx context.Context, s Store, crs []*CVERecord) {
	err := s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		for _, cr := range crs {
			if err := tx.CreateCVERecord(cr); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func diff(t *testing.T, want, got interface{}, opts ...cmp.Option) {
	t.Helper()
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
