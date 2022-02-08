// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package worker

import (
	"context"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/worker/store"
)

const clearString = "**CLEAR**"

var clearCVE = &cveschema.CVE{}

func modify(r, m *store.CVERecord) *store.CVERecord {
	modString := func(p *string, s string) {
		if s == clearString {
			*p = ""
		} else if s != "" {
			*p = s
		}
	}

	c := *r
	modString(&c.BlobHash, m.BlobHash)
	modString(&c.CommitHash, m.CommitHash)
	modString(&c.CVEState, m.CVEState)
	if m.TriageState != "" {
		if m.TriageState == clearString {
			c.TriageState = ""
		} else {
			c.TriageState = m.TriageState
		}
	}
	modString(&c.TriageStateReason, m.TriageStateReason)
	modString(&c.Module, m.Module)
	if m.CVE == clearCVE {
		c.CVE = nil
	} else if m.CVE != nil {
		c.CVE = m.CVE
	}
	modString(&c.IssueReference, m.IssueReference)
	if !m.IssueCreatedAt.IsZero() {
		panic("unsupported modification")
	}
	if m.ReferenceURLs != nil {
		c.ReferenceURLs = m.ReferenceURLs
	}
	if m.History != nil {
		c.History = m.History
	}
	return &c
}

func TestNewCVERecord(t *testing.T) {
	// Check that NewCVERecord with a TriageState gives a valid CVERecord.
	repo, err := gitrepo.ReadTxtarRepo(testRepoPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commit := headCommit(t, repo)
	pathname := "2021/0xxx/CVE-2021-0001.json"
	cve, bh := readCVE(t, repo, commit, pathname)
	cr := store.NewCVERecord(cve, pathname, bh, commit)
	cr.TriageState = store.TriageStateNeedsIssue
	if err := cr.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDoUpdate(t *testing.T) {
	ctx := context.Background()
	repo, err := gitrepo.ReadTxtarRepo(testRepoPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commit := headCommit(t, repo)
	purl := getPkgsiteURL(t)
	needsIssue := func(cve *cveschema.CVE) (*triageResult, error) {
		return TriageCVE(ctx, cve, purl)
	}

	commitHash := commit.Hash.String()
	knownVulns := []string{"CVE-2020-9283"}

	paths := []string{
		"2021/0xxx/CVE-2021-0001.json",
		"2021/0xxx/CVE-2021-0010.json",
		"2021/1xxx/CVE-2021-1384.json",
		"2020/9xxx/CVE-2020-9283.json",
	}

	var (
		cves       []*cveschema.CVE
		blobHashes []string
	)
	for _, p := range paths {
		cve, bh := readCVE(t, repo, commit, p)
		cves = append(cves, cve)
		blobHashes = append(blobHashes, bh)
	}
	// CVERecords after the above CVEs are added to an empty DB.
	var rs []*store.CVERecord
	for i := 0; i < len(cves); i++ {
		r := store.NewCVERecord(cves[i], paths[i], blobHashes[i], commit)
		rs = append(rs, r)
	}
	rs[0].TriageState = store.TriageStateNeedsIssue // a public CVE, has a golang.org path
	rs[0].Module = "golang.org/x/mod"
	rs[0].CVE = cves[0]
	rs[1].TriageState = store.TriageStateNoActionNeeded // state is reserved
	rs[2].TriageState = store.TriageStateNoActionNeeded // state is rejected
	rs[3].TriageState = store.TriageStateHasVuln

	for _, test := range []struct {
		name string
		cur  []*store.CVERecord // current state of DB
		want []*store.CVERecord // expected state after update
	}{
		{
			name: "empty",
			cur:  nil,
			want: rs,
		},
		{
			name: "no change",
			cur:  rs,
			want: rs,
		},
		{
			name: "pre-issue changes",
			cur: []*store.CVERecord{
				// NoActionNeeded -> NeedsIssue
				modify(rs[0], &store.CVERecord{
					BlobHash:    "x", // if we don't use a different blob hash, no update will happen
					TriageState: store.TriageStateNoActionNeeded,
				}),
				// NeedsIssue -> NoActionNeeded
				modify(rs[1], &store.CVERecord{
					BlobHash:    "x",
					TriageState: store.TriageStateNeedsIssue,
					Module:      "something",
					CVE:         cves[1],
				}),
				// NoActionNeeded, triage state stays the same but other fields change.
				modify(rs[2], &store.CVERecord{
					TriageState: store.TriageStateNoActionNeeded,
				}),
			},
			want: []*store.CVERecord{
				modify(rs[0], &store.CVERecord{
					History: []*store.CVERecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    cveschema.StatePublic,
						TriageState: store.TriageStateNoActionNeeded,
					}},
				}),
				modify(rs[1], &store.CVERecord{
					Module: clearString,
					CVE:    clearCVE,
					History: []*store.CVERecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    cveschema.StateReserved,
						TriageState: store.TriageStateNeedsIssue,
					}},
				}),
				rs[2],
				rs[3],
			},
		},
		{
			name: "post-issue changes",
			cur: []*store.CVERecord{
				// IssueCreated -> Updated
				modify(rs[0], &store.CVERecord{
					BlobHash:    "x",
					TriageState: store.TriageStateIssueCreated,
				}),
				modify(rs[1], &store.CVERecord{
					BlobHash:    "x",
					TriageState: store.TriageStateUpdatedSinceIssueCreation,
				}),
			},
			want: []*store.CVERecord{
				modify(rs[0], &store.CVERecord{
					TriageState:       store.TriageStateUpdatedSinceIssueCreation,
					TriageStateReason: `CVE changed; affected module = "golang.org/x/mod"`,
					History: []*store.CVERecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    cveschema.StatePublic,
						TriageState: store.TriageStateIssueCreated,
					}},
				}),
				modify(rs[1], &store.CVERecord{
					TriageState:       store.TriageStateUpdatedSinceIssueCreation,
					TriageStateReason: `CVE changed; affected module = ""`,
				}),
				rs[2],
				rs[3],
			},
		},
		{
			name: "false positive no Go URLs",
			cur: []*store.CVERecord{
				// FalsePositive; no change
				modify(rs[0], &store.CVERecord{
					BlobHash:    "x",
					TriageState: store.TriageStateFalsePositive,
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
						"https://golang.org/x/mod",
					},
				}),
			},
			want: []*store.CVERecord{
				modify(rs[0], &store.CVERecord{
					TriageState: store.TriageStateFalsePositive,
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
						"https://golang.org/x/mod",
					},
				}),
				rs[1], rs[2], rs[3],
			},
		},
		{
			name: "false positive new Go URLs",
			cur: []*store.CVERecord{
				// FalsePositive; no change
				modify(rs[0], &store.CVERecord{
					BlobHash:    "x",
					TriageState: store.TriageStateFalsePositive,
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
					},
				}),
			},
			want: []*store.CVERecord{
				modify(rs[0], &store.CVERecord{
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
					},
					History: []*store.CVERecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    "PUBLIC",
						TriageState: "FalsePositive",
					}},
				}),
				rs[1], rs[2], rs[3],
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mstore := store.NewMemStore()
			createCVERecords(t, mstore, test.cur)
			if _, err := newCVEUpdater(repo, commit, mstore, knownVulns, needsIssue).update(ctx); err != nil {
				t.Fatal(err)
			}
			got := mstore.CVERecords()
			want := map[string]*store.CVERecord{}
			for _, cr := range test.want {
				want[cr.ID] = cr
			}
			if diff := cmp.Diff(want, got,
				cmpopts.IgnoreFields(store.CVERecord{}, "TriageStateReason"),
				cmpopts.IgnoreFields(store.CVERecordSnapshot{}, "TriageStateReason")); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestGroupFilesByDirectory(t *testing.T) {
	for _, test := range []struct {
		in   []cvelistrepo.File
		want [][]cvelistrepo.File
	}{
		{in: nil, want: nil},
		{
			in:   []cvelistrepo.File{{DirPath: "a"}},
			want: [][]cvelistrepo.File{{{DirPath: "a"}}},
		},
		{
			in: []cvelistrepo.File{
				{DirPath: "a", Filename: "f1"},
				{DirPath: "a", Filename: "f2"},
			},
			want: [][]cvelistrepo.File{{
				{DirPath: "a", Filename: "f1"},
				{DirPath: "a", Filename: "f2"},
			}},
		},
		{
			in: []cvelistrepo.File{
				{DirPath: "a", Filename: "f1"},
				{DirPath: "a", Filename: "f2"},
				{DirPath: "b", Filename: "f1"},
				{DirPath: "c", Filename: "f1"},
				{DirPath: "c", Filename: "f2"},
			},
			want: [][]cvelistrepo.File{
				{
					{DirPath: "a", Filename: "f1"},
					{DirPath: "a", Filename: "f2"},
				},
				{
					{DirPath: "b", Filename: "f1"},
				},
				{
					{DirPath: "c", Filename: "f1"},
					{DirPath: "c", Filename: "f2"},
				},
			},
		},
	} {
		got, err := groupFilesByDirectory(test.in)
		if err != nil {
			t.Fatalf("%v: %v", test.in, err)
		}
		if diff := cmp.Diff(got, test.want, cmp.AllowUnexported(cvelistrepo.File{})); diff != "" {
			t.Errorf("%v: (-want, +got)\n%s", test.in, diff)
		}
	}

	_, err := groupFilesByDirectory([]cvelistrepo.File{{DirPath: "a"}, {DirPath: "b"}, {DirPath: "a"}})
	if err == nil {
		t.Error("got nil, want error")
	}
}

func readCVE(t *testing.T, repo *git.Repository, commit *object.Commit, path string) (*cveschema.CVE, string) {
	cve, blobHash, err := ReadCVEAtPath(commit, path)
	if err != nil {
		t.Fatal(err)
	}
	return cve, blobHash
}

func createCVERecords(t *testing.T, s store.Store, crs []*store.CVERecord) {
	err := s.RunTransaction(context.Background(), func(_ context.Context, tx store.Transaction) error {
		for _, cr := range crs {
			copy := *cr
			if err := tx.CreateCVERecord(&copy); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func createGHSARecords(t *testing.T, s store.Store, grs []*store.GHSARecord) {
	err := s.RunTransaction(context.Background(), func(_ context.Context, tx store.Transaction) error {
		for _, gr := range grs {
			copy := *gr
			if err := tx.CreateGHSARecord(&copy); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// headCommit returns the commit at the repo HEAD.
func headCommit(t *testing.T, repo *git.Repository) *object.Commit {
	h, err := gitrepo.HeadHash(repo)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(h)
	if err != nil {
		t.Fatal(err)
	}
	return commit
}
