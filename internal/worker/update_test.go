// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package worker

import (
	"context"
	"errors"
	"flag"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/cvelistrepo"
	"golang.org/x/vulndb/internal/cveutils"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker/store"
)

var usePkgsite = flag.Bool("pkgsite", false, "use pkg.go.dev for tests")

const clearString = "**CLEAR**"

var clearCVE = &cve4.CVE{}

func modify(r, m *store.CVE4Record) *store.CVE4Record {
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

func TestNewCVE4Record(t *testing.T) {
	// Check that NewCVE4Record with a TriageState gives a valid CVE4Record.
	repo, err := gitrepo.ReadTxtarRepo(testRepoPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commit := headCommit(t, repo)
	pathname := "2021/0xxx/CVE-2021-0001.json"
	cve, bh := readCVE4(t, repo, commit, pathname)
	cr := store.NewCVE4Record(cve, pathname, bh, commit)
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
	cf, err := pkgsite.CacheFile(t)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := pkgsite.TestClient(t, *usePkgsite, cf)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := report.NewTestClient(map[string]*report.Report{
		"data/reports/GO-1999-0001.yaml": {CVEs: []string{"CVE-2020-9283"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	needsIssue := func(cve *cve4.CVE) (*cveutils.TriageResult, error) {
		return cveutils.TriageCVE(ctx, cve, pc)
	}

	commitHash := commit.Hash.String()

	paths := []string{
		"2021/0xxx/CVE-2021-0001.json",
		"2021/0xxx/CVE-2021-0010.json",
		"2021/1xxx/CVE-2021-1384.json",
		"2020/9xxx/CVE-2020-9283.json",
		"2022/39xxx/CVE-2022-39213.json",
	}

	var (
		cves       []*cve4.CVE
		blobHashes []string
	)
	for _, p := range paths {
		cve, bh := readCVE4(t, repo, commit, p)
		cves = append(cves, cve)
		blobHashes = append(blobHashes, bh)
	}
	// Expected CVE4Records after the above CVEs are added to an empty DB.
	var rs []*store.CVE4Record
	for i := 0; i < len(cves); i++ {
		r := store.NewCVE4Record(cves[i], paths[i], blobHashes[i], commit)
		rs = append(rs, r)
	}
	rs[0].TriageState = store.TriageStateNeedsIssue // a public CVE, has a golang.org path
	rs[0].Module = "golang.org/x/mod"
	rs[0].CVE = cves[0]

	rs[1].TriageState = store.TriageStateNoActionNeeded // state is reserved
	rs[2].TriageState = store.TriageStateNoActionNeeded // state is rejected
	rs[3].TriageState = store.TriageStateHasVuln

	rs[4].TriageState = store.TriageStateNeedsIssue
	rs[4].Module = "github.com/pandatix/go-cvss"
	rs[4].CVE = cves[4]

	for _, test := range []struct {
		name       string
		curCVEs    []*store.CVE4Record       // current state of CVEs collection
		curGHSAs   []*store.LegacyGHSARecord // current state of GHSAs collection
		want       []*store.CVE4Record       // expected state of CVEs collection after update
		wantUpdate *store.CommitUpdateRecord // expected update record
	}{
		{
			name:    "empty",
			curCVEs: nil,
			want:    rs,
			wantUpdate: &store.CommitUpdateRecord{
				NumTotal:     5,
				NumProcessed: 5,
				NumAdded:     5,
			},
		},
		{
			name:    "no change",
			curCVEs: rs,
			want:    rs,
			wantUpdate: &store.CommitUpdateRecord{
				NumTotal:     5,
				NumProcessed: 5,
				NumAdded:     0,
			},
		},
		{
			name: "pre-issue changes",
			curCVEs: []*store.CVE4Record{
				// NoActionNeeded -> NeedsIssue
				modify(rs[0], &store.CVE4Record{
					BlobHash:    "x", // if we don't use a different blob hash, no update will happen
					TriageState: store.TriageStateNoActionNeeded,
				}),
				// NeedsIssue -> NoActionNeeded
				modify(rs[1], &store.CVE4Record{
					BlobHash:    "x",
					TriageState: store.TriageStateNeedsIssue,
					Module:      "something",
					CVE:         cves[1],
				}),
				// NoActionNeeded, triage state stays the same but other fields change.
				modify(rs[2], &store.CVE4Record{
					TriageState: store.TriageStateNoActionNeeded,
				}),
			},
			want: []*store.CVE4Record{
				modify(rs[0], &store.CVE4Record{
					History: []*store.CVE4RecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    cve4.StatePublic,
						TriageState: store.TriageStateNoActionNeeded,
					}},
				}),
				modify(rs[1], &store.CVE4Record{
					Module: clearString,
					CVE:    clearCVE,
					History: []*store.CVE4RecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    cve4.StateReserved,
						TriageState: store.TriageStateNeedsIssue,
					}},
				}),
				rs[2],
				rs[3],
				rs[4],
			},
			wantUpdate: &store.CommitUpdateRecord{
				NumTotal:     5,
				NumProcessed: 5,
				NumAdded:     2,
				NumModified:  2,
			},
		},
		{
			name: "post-issue changes",
			curCVEs: []*store.CVE4Record{
				// IssueCreated -> Updated
				modify(rs[0], &store.CVE4Record{
					BlobHash:    "x",
					TriageState: store.TriageStateIssueCreated,
				}),
				modify(rs[1], &store.CVE4Record{
					BlobHash:    "x",
					TriageState: store.TriageStateUpdatedSinceIssueCreation,
				}),
			},
			want: []*store.CVE4Record{
				modify(rs[0], &store.CVE4Record{
					TriageState:       store.TriageStateUpdatedSinceIssueCreation,
					TriageStateReason: `CVE changed; affected module = "golang.org/x/mod"`,
					History: []*store.CVE4RecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    cve4.StatePublic,
						TriageState: store.TriageStateIssueCreated,
					}},
				}),
				modify(rs[1], &store.CVE4Record{
					TriageState:       store.TriageStateUpdatedSinceIssueCreation,
					TriageStateReason: `CVE changed; affected module = ""`,
				}),
				rs[2],
				rs[3],
				rs[4],
			},
			wantUpdate: &store.CommitUpdateRecord{
				NumTotal:     5,
				NumProcessed: 5,
				NumAdded:     3,
				NumModified:  2,
			},
		},
		{
			name: "false positive no Go URLs",
			curCVEs: []*store.CVE4Record{
				// FalsePositive; no change
				modify(rs[0], &store.CVE4Record{
					BlobHash:    "x",
					TriageState: store.TriageStateFalsePositive,
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
						"https://golang.org/x/mod",
					},
				}),
			},
			want: []*store.CVE4Record{
				modify(rs[0], &store.CVE4Record{
					TriageState: store.TriageStateFalsePositive,
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
						"https://golang.org/x/mod",
					},
				}),
				rs[1], rs[2], rs[3], rs[4],
			},
			wantUpdate: &store.CommitUpdateRecord{
				NumTotal:     5,
				NumProcessed: 5,
				NumAdded:     4,
				NumModified:  1,
			},
		},
		{
			name: "false positive new Go URLs",
			curCVEs: []*store.CVE4Record{
				// FalsePositive; no change
				modify(rs[0], &store.CVE4Record{
					BlobHash:    "x",
					TriageState: store.TriageStateFalsePositive,
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
					},
				}),
			},
			want: []*store.CVE4Record{
				modify(rs[0], &store.CVE4Record{
					ReferenceURLs: []string{
						"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00477.html",
					},
					History: []*store.CVE4RecordSnapshot{{
						CommitHash:  commitHash,
						CVEState:    "PUBLIC",
						TriageState: "FalsePositive",
					}},
				}),
				rs[1], rs[2], rs[3], rs[4],
			},
			wantUpdate: &store.CommitUpdateRecord{
				NumTotal:     5,
				NumProcessed: 5,
				NumAdded:     4,
				NumModified:  1,
			},
		},
		{
			name: "alias already created",
			curCVEs: []*store.CVE4Record{rs[0],
				rs[1], rs[2], rs[3]},
			curGHSAs: []*store.LegacyGHSARecord{
				{
					GHSA: &ghsa.SecurityAdvisory{
						ID: "GHSA-xhmf-mmv2-4hhx",
					},
					TriageState: store.TriageStateIssueCreated,
				},
			},
			want: []*store.CVE4Record{
				rs[0],
				rs[1], rs[2], rs[3], modify(rs[4], &store.CVE4Record{
					TriageState: store.TriageStateAlias,
				}),
			},
			wantUpdate: &store.CommitUpdateRecord{
				NumTotal:     5,
				NumProcessed: 5,
				NumAdded:     1,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mstore := store.NewMemStore()
			createCVE4Records(t, mstore, test.curCVEs)
			createLegacyGHSARecords(t, mstore, test.curGHSAs)
			newCVEUpdater(repo, commit, mstore, rc, needsIssue).update(ctx)
			got := mstore.CVE4Records()
			want := map[string]*store.CVE4Record{}
			for _, cr := range test.want {
				want[cr.ID] = cr
			}
			if diff := cmp.Diff(want, got,
				cmpopts.IgnoreFields(store.CVE4Record{}, "TriageStateReason"),
				cmpopts.IgnoreFields(store.CVE4RecordSnapshot{}, "TriageStateReason")); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			gotUpdates, err := mstore.ListCommitUpdateRecords(ctx, -1)
			if err != nil {
				t.Fatal(err)
			}
			wantUpdates := []*store.CommitUpdateRecord{test.wantUpdate}
			if diff := cmp.Diff(wantUpdates, gotUpdates,
				cmpopts.IgnoreFields(store.CommitUpdateRecord{}, "ID",
					"StartedAt", "EndedAt", "CommitHash", "CommitTime",
					"UpdatedAt")); diff != "" {
				t.Errorf("updates mismatch (-want, +got):\n%s", diff)
			}
			if len(gotUpdates) > 0 {
				got := gotUpdates[0]
				if got.StartedAt.IsZero() {
					t.Error("CommitUpdateRecord.StartedAt is zero, want non-zero")
				}
				if got.EndedAt.IsZero() {
					t.Error("CommitUpdateRecord.EndedAt is zero, want non-zero")
				}
				if got.Error != "" {
					t.Errorf("CommitUpdateRecord.Error = %s, want no error", got.Error)
				}
			}
		})
	}
}

func TestDoUpdateError(t *testing.T) {
	ctx := context.Background()
	repo, commit, err := gitrepo.TxtarRepoAndHead(testRepoPath)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := report.NewTestClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	needsIssue := func(cve *cve4.CVE) (*cveutils.TriageResult, error) { return nil, nil }

	for _, test := range []struct {
		name                                      string
		errOnRunTransaction, errOnSetCommitUpdate bool
		wantErrs                                  []error
		// whether to expect a meaningful update record
		wantValidUpdateRecord bool
	}{
		{
			name:                  "transaction error",
			errOnRunTransaction:   true,
			wantErrs:              []error{transactionErr},
			wantValidUpdateRecord: true,
		},
		{
			name:                 "commit error",
			errOnSetCommitUpdate: true,
			wantErrs:             []error{commitUpdateErr},
		},
		{
			name:                 "transaction and commit error",
			errOnRunTransaction:  true,
			errOnSetCommitUpdate: true,
			wantErrs:             []error{transactionErr, commitUpdateErr},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mstore := newErrStore(test.errOnRunTransaction, test.errOnSetCommitUpdate)
			err := newCVEUpdater(repo, commit, mstore, rc, needsIssue).update(ctx)
			for _, wantErr := range test.wantErrs {
				if !errors.Is(err, wantErr) {
					t.Fatalf("newCVEUpdater: want err = %v, got %v", wantErr, err)
				}
			}

			gotUpdates, err := mstore.ListCommitUpdateRecords(ctx, -1)
			if err != nil {
				t.Fatalf("ListCommitUpdateRecords = %s", err)
			}
			if len(gotUpdates) == 0 {
				t.Fatalf("no update record created")
			}
			got := gotUpdates[0]
			if got.StartedAt.IsZero() {
				t.Error("CommitUpdateRecord.StartedAt is zero, want non-zero")
			}

			if test.wantValidUpdateRecord {
				if got.EndedAt.IsZero() {
					t.Error("CommitUpdateRecord.EndedAt is zero, want non-zero")
				}
				if got.Error == "" {
					t.Error("CommitUpdateRecord.Error is empty, want an error")
				}
			}
		})
	}
}

type transactionErrStore struct {
	*store.MemStore
	errOnRunTransaction, errOnSetCommitUpdate bool
}

func newErrStore(errOnRunTransaction, errOnSetCommitUpdate bool) *transactionErrStore {
	return &transactionErrStore{
		MemStore:             store.NewMemStore(),
		errOnRunTransaction:  errOnRunTransaction,
		errOnSetCommitUpdate: errOnSetCommitUpdate,
	}
}

var transactionErr = errors.New("transaction error occurred")

func (s *transactionErrStore) RunTransaction(ctx context.Context, f func(context.Context, store.Transaction) error) error {
	if s.errOnRunTransaction {
		return transactionErr
	}
	return s.MemStore.RunTransaction(ctx, f)
}

var commitUpdateErr = errors.New("commit update occurred")

func (s *transactionErrStore) SetCommitUpdateRecord(ctx context.Context, ur *store.CommitUpdateRecord) error {
	if s.errOnSetCommitUpdate {
		return commitUpdateErr
	}
	return s.MemStore.SetCommitUpdateRecord(ctx, ur)
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

func readCVE4(t *testing.T, repo *git.Repository, commit *object.Commit, path string) (*cve4.CVE, string) {
	cve, blobHash, err := ReadCVEAtPath(commit, path)
	if err != nil {
		t.Fatal(err)
	}
	return cve, blobHash
}

func createCVE4Records(t *testing.T, s store.Store, crs []*store.CVE4Record) {
	err := s.RunTransaction(context.Background(), func(ctx context.Context, tx store.Transaction) error {
		for _, cr := range crs {
			copy := *cr
			if err := tx.CreateCVE4Record(&copy); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func createLegacyGHSARecords(t *testing.T, s store.Store, grs []*store.LegacyGHSARecord) {
	err := s.RunTransaction(context.Background(), func(ctx context.Context, tx store.Transaction) error {
		for _, gr := range grs {
			copy := *gr
			if err := tx.CreateLegacyGHSARecord(&copy); err != nil {
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
