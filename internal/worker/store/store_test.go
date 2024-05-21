// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/ghsa"
)

func must(err error) func(*testing.T) {
	return func(t *testing.T) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func must1[T any](x T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return x
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
	t.Run("GHSAs", func(t *testing.T) {
		testGHSAs(t, s)
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
	must(s.CreateCommitUpdateRecord(ctx, u1))(t)
	u1.EndedAt = u1.StartedAt.Add(10 * time.Minute)
	u1.NumAdded = 100
	must(s.SetCommitUpdateRecord(ctx, u1))(t)
	u2 := &CommitUpdateRecord{
		StartedAt:  start.Add(time.Hour),
		CommitHash: "def",
		NumTotal:   80,
	}
	must(s.CreateCommitUpdateRecord(ctx, u2))(t)
	u2.EndedAt = u2.StartedAt.Add(8 * time.Minute)
	u2.NumAdded = 40
	u2.NumModified = 40
	must(s.SetCommitUpdateRecord(ctx, u2))(t)
	got := must1(s.ListCommitUpdateRecords(ctx, 0))(t)
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

	crs := []*CVE4Record{
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

	getCVE4Records := func(startID, endID string) []*CVE4Record {
		var got []*CVE4Record
		err := s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
			var err error
			got, err = tx.GetCVE4Records(startID, endID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	createCVE4Records(t, ctx, s, crs)

	diff(t, crs[:1], getCVE4Records(id1, id1))
	diff(t, crs[1:], getCVE4Records(id2, id3))

	// Test SetCVE4Record.

	set := func(r *CVE4Record) *CVE4Record {
		must(s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
			return tx.SetRecord(r)
		}))(t)
		return must1(s.GetRecord(ctx, r.ID))(t).(*CVE4Record)
	}

	// Make sure the first record is the same that we created.
	r := must1(s.GetRecord(ctx, id1))(t)
	got := r.(*CVE4Record)
	diff(t, crs[0], got)

	// Change the state and the commit hash.
	got.CVEState = cve4.StateRejected
	got.CommitHash = "999"
	set(got)
	want := *crs[0]
	want.CVEState = cve4.StateRejected
	want.CommitHash = "999"
	diff(t, &want, got)

	gotNoAction := must1(s.ListCVE4RecordsWithTriageState(ctx, TriageStateNoActionNeeded))(t)
	diff(t, crs[1:], gotNoAction)
}

func testDirHashes(t *testing.T, s Store) {
	ctx := context.Background()
	const dir = "a/b/c"
	got := must1(s.GetDirectoryHash(ctx, dir))(t)
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	const want = "123"
	must(s.SetDirectoryHash(ctx, "a/b/c", want))(t)
	got = must1(s.GetDirectoryHash(ctx, dir))(t)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

var (
	ghsa1, ghsa2, ghsa3, ghsa4, ghsa5 = "GHSA-xxxx-yyyy-1111", "GHSA-xxxx-yyyy-2222", "GHSA-xxxx-yyyy-3333", "GHSA-xxxx-yyyy-4444", "GHSA-xxxx-yyyy-5555"
)

func testGHSAs(t *testing.T, s Store) {
	ctx := context.Background()
	// Create two records.
	gs := []*LegacyGHSARecord{
		{
			GHSA:        &ghsa.SecurityAdvisory{ID: ghsa1, Summary: "one"},
			TriageState: TriageStateNeedsIssue,
		},
		{
			GHSA:        &ghsa.SecurityAdvisory{ID: ghsa2, Summary: "two"},
			TriageState: TriageStateNeedsIssue,
		},
	}
	must(s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		for _, g := range gs {
			if err := tx.CreateRecord(g); err != nil {
				return err
			}
		}
		return nil
	}))(t)
	// Modify one of them.
	gs[1].TriageState = TriageStateIssueCreated
	must(s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.SetRecord(gs[1])
	}))(t)
	// Retrieve and compare.
	var got []*LegacyGHSARecord
	must(s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		var err error
		got, err = tx.GetLegacyGHSARecords()
		return err
	}))(t)
	if len(got) != len(gs) {
		t.Fatalf("got %d records, want %d", len(got), len(gs))
	}
	sort.Slice(got, func(i, j int) bool { return got[i].GHSA.ID < got[j].GHSA.ID })
	if diff := cmp.Diff(gs, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}

	// Retrieve one record by GHSA ID.
	var got0 *LegacyGHSARecord
	must(s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		r, err := tx.GetRecord(gs[0].GetID())
		if err != nil {
			return err
		}
		got0 = r.(*LegacyGHSARecord)
		return nil
	}))(t)
	if got, want := got0, gs[0]; !cmp.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func createCVE4Records(t *testing.T, ctx context.Context, s Store, crs []*CVE4Record) {
	must(s.RunTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		for _, cr := range crs {
			if err := tx.CreateRecord(cr); err != nil {
				return err
			}
		}
		return nil
	}))(t)
}

func diff(t *testing.T, want, got interface{}, opts ...cmp.Option) {
	t.Helper()
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}
