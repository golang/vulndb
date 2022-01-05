// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package worker

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/worker/log"
	"golang.org/x/vulndb/internal/worker/store"
)

func TestCheckUpdate(t *testing.T) {
	ctx := context.Background()
	tm := time.Date(2021, 1, 26, 0, 0, 0, 0, time.Local)
	repo, err := gitrepo.ReadTxtarRepo("../cvelistrepo/testdata/basic.txtar", tm)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		latestUpdate *store.CommitUpdateRecord
		want         string // non-empty => substring of error message
	}{
		// no latest update, no problem
		{nil, ""},
		// latest update finished and commit is earlier; no problem
		{
			&store.CommitUpdateRecord{
				EndedAt:    time.Now(),
				CommitHash: "abc",
				CommitTime: tm.Add(-time.Hour),
			},
			"",
		},
		// latest update was recent and didn't finish
		{
			&store.CommitUpdateRecord{
				StartedAt:  time.Now().Add(-90 * time.Minute),
				CommitHash: "abc",
				CommitTime: tm.Add(-time.Hour),
			},
			"not finish",
		},
		// latest update finished with error
		{
			&store.CommitUpdateRecord{
				CommitHash: "abc",
				CommitTime: tm.Add(-time.Hour),
				EndedAt:    time.Now(),
				Error:      "bad",
			},
			"with error",
		},
		// latest update finished on a later commit
		{
			&store.CommitUpdateRecord{
				EndedAt:    time.Now(),
				CommitHash: "abc",
				CommitTime: tm.Add(time.Hour),
			},
			"before",
		},
	} {
		mstore := store.NewMemStore()
		if err := InsertFalsePositives(ctx, mstore); err != nil {
			t.Fatal(err)
		}
		if test.latestUpdate != nil {
			if err := mstore.CreateCommitUpdateRecord(ctx, test.latestUpdate); err != nil {
				t.Fatal(err)
			}
		}
		got := checkUpdate(ctx, repo, headCommit(t, repo).Hash, mstore)
		if got == nil && test.want != "" {
			t.Errorf("%+v:\ngot no error, wanted %q", test.latestUpdate, test.want)
		} else if got != nil && !strings.Contains(got.Error(), test.want) {
			t.Errorf("%+v:\ngot '%s', does not contain %q", test.latestUpdate, got, test.want)
		}
	}
}

func TestCreateIssues(t *testing.T) {
	ctx := log.WithLineLogger(context.Background())
	mstore := store.NewMemStore()
	ic := issues.NewFakeClient()

	crs := []*store.CVERecord{
		{
			ID:         "ID1",
			BlobHash:   "bh1",
			CommitHash: "ch",
			Path:       "path1",
			CVE: &cveschema.CVE{
				Metadata: cveschema.Metadata{
					ID: "ID1",
				},
			},
			TriageState: store.TriageStateNeedsIssue,
		},
		{
			ID:          "ID2",
			BlobHash:    "bh2",
			CommitHash:  "ch",
			Path:        "path2",
			TriageState: store.TriageStateNoActionNeeded,
		},
		{
			ID:          "ID3",
			BlobHash:    "bh3",
			CommitHash:  "ch",
			Path:        "path3",
			TriageState: store.TriageStateIssueCreated,
		},
	}
	createCVERecords(t, mstore, crs)

	if err := CreateIssues(ctx, mstore, ic, 0); err != nil {
		t.Fatal(err)
	}

	var wants []*store.CVERecord
	for _, r := range crs {
		copy := *r
		wants = append(wants, &copy)
	}
	wants[0].TriageState = store.TriageStateIssueCreated
	wants[0].IssueReference = "inMemory#1"

	gotRecs := mstore.CVERecords()
	if len(gotRecs) != len(wants) {
		t.Fatalf("wrong number of records: got %d, want %d", len(gotRecs), len(wants))
	}
	for _, want := range wants {
		got := gotRecs[want.ID]
		if !cmp.Equal(got, want, cmpopts.IgnoreFields(store.CVERecord{}, "IssueCreatedAt")) {
			t.Errorf("got  %+v\nwant %+v", got, want)
		}
	}
}

func TestNewBody(t *testing.T) {
	r := &store.CVERecord{
		ID:     "ID1",
		Module: "a.Module",
		CVE: &cveschema.CVE{
			Description: cveschema.Description{
				Data: []cveschema.LangString{{
					Lang:  "eng",
					Value: "a description",
				}},
			},
		},
	}
	got, err := newBody(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `In [ID1](https://github.com/CVEProject/cvelist/tree//), the reference URL [a.Module](a.Module) (and possibly others) refers to something in Go.

` + "```" + `
module: a.Module
description: |
  a description
cves:
- ID1

` + "```" + `

See [doc/triage.md](https://github.com/golang/vulndb/blob/master/doc/triage.md)
for instructions on how to triage this report.
`
	if diff := cmp.Diff(unindent(want), got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

// unindent removes leading whitespace from s.
// It first finds the line beginning with the fewest space and tab characters.
// It then removes that many characters from every line.
func unindent(s string) string {
	lines := strings.Split(s, "\n")
	min := math.MaxInt
	for _, l := range lines {
		if len(l) == 0 {
			continue
		}
		n := 0
		for _, r := range l {
			if r != ' ' && r != '\t' {
				break
			}
			n++
		}
		if n < min {
			min = n
		}
	}
	for i, l := range lines {
		if len(l) > 0 {
			lines[i] = l[min:]
		}
	}
	return strings.Join(lines, "\n")
}
