// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package worker

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/issues/githubtest"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker/store"
)

const testRepoPath = "testdata/basic.txtar"

var realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")

func TestCheckUpdate(t *testing.T) {
	ctx := context.Background()
	tm := time.Date(2021, 1, 26, 0, 0, 0, 0, time.Local)
	repo, err := gitrepo.ReadTxtarRepo(testRepoPath, tm)
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
		if err := updateFalsePositives(ctx, mstore); err != nil {
			t.Fatal(err)
		}
		if test.latestUpdate != nil {
			if err := mstore.CreateCommitUpdateRecord(ctx, test.latestUpdate); err != nil {
				t.Fatal(err)
			}
		}
		got := checkCVEUpdate(ctx, headCommit(t, repo), mstore)
		if got == nil && test.want != "" {
			t.Errorf("%+v:\ngot no error, wanted %q", test.latestUpdate, test.want)
		} else if got != nil && !strings.Contains(got.Error(), test.want) {
			t.Errorf("%+v:\ngot '%s', does not contain %q", test.latestUpdate, got, test.want)
		}
	}
}

func TestCreateIssues(t *testing.T) {
	ctx := context.Background()
	mstore := store.NewMemStore()

	ic, mux := githubtest.Setup(ctx, t, &issues.Config{
		Owner: githubtest.TestOwner,
		Repo:  githubtest.TestRepo,
		Token: githubtest.TestToken,
	})

	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/issues", githubtest.TestOwner, githubtest.TestRepo), func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			fmt.Fprintf(w, `[{"number":%d},{"number":%d}]`, 1, 2)
		case http.MethodPost:
			fmt.Fprintf(w, `{"number":%d}`, 1)
		}
	})

	ctime := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)

	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	crs := []*store.CVERecord{
		{
			ID:         "ID1",
			BlobHash:   "bh1",
			CommitHash: "ch",
			CommitTime: ctime,
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
			CommitTime:  ctime,
			Path:        "path2",
			TriageState: store.TriageStateNoActionNeeded,
		},
		{
			ID:          "ID3",
			BlobHash:    "bh3",
			CommitHash:  "ch",
			CommitTime:  ctime,
			Path:        "path3",
			TriageState: store.TriageStateIssueCreated,
		},
	}
	createCVERecords(t, mstore, crs)
	grs := []*store.GHSARecord{
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    "g1",
				Vulns: []*ghsa.Vuln{{Package: "p1"}},
			},
			TriageState: store.TriageStateNeedsIssue,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    "g2",
				Vulns: []*ghsa.Vuln{{Package: "p2"}},
			},
			TriageState: store.TriageStateNoActionNeeded,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    "g3",
				Vulns: []*ghsa.Vuln{{Package: "p3"}},
			},
			TriageState: store.TriageStateIssueCreated,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    "g4",
				Vulns: []*ghsa.Vuln{{Package: "p4"}},
			},
			TriageState: store.TriageStateAlias,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:          "g5",
				Vulns:       []*ghsa.Vuln{{Package: "p1"}},
				Identifiers: []ghsa.Identifier{{Type: "GHSA", Value: "g5"}},
			},
			TriageState: store.TriageStateNeedsIssue,
		},
	}
	createGHSARecords(t, mstore, grs)

	// Add an existing report with GHSA "g5".
	rc, err := report.NewTestClient(map[string]*report.Report{
		"data/reports/GO-1999-0001.yaml": {GHSAs: []string{"g5"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := CreateIssues(ctx, mstore, ic, pc, rc, 0); err != nil {
		t.Fatal(err)
	}

	var wantCVERecords []*store.CVERecord
	for _, r := range crs {
		copy := *r
		wantCVERecords = append(wantCVERecords, &copy)
	}
	wantCVERecords[0].TriageState = store.TriageStateIssueCreated
	wantCVERecords[0].IssueReference = "https://github.com/test-owner/test-repo/issues/1"

	gotCVERecs := mstore.CVERecords()
	if len(gotCVERecs) != len(wantCVERecords) {
		t.Fatalf("wrong number of records: got %d, want %d", len(gotCVERecs), len(wantCVERecords))
	}
	for _, want := range wantCVERecords {
		got := gotCVERecs[want.ID]
		if !cmp.Equal(got, want, cmpopts.IgnoreFields(store.CVERecord{}, "IssueCreatedAt")) {
			t.Errorf("\ngot  %+v\nwant %+v", got, want)
		}
	}

	var wantGHSARecs []*store.GHSARecord
	for _, r := range grs {
		copy := *r
		wantGHSARecs = append(wantGHSARecs, &copy)
	}
	wantGHSARecs[0].TriageState = store.TriageStateIssueCreated
	wantGHSARecs[0].IssueReference = "https://github.com/test-owner/test-repo/issues/1"

	// A report already exists for GHSA "g5".
	wantGHSARecs[4].TriageState = store.TriageStateHasVuln

	gotGHSARecs := getGHSARecordsSorted(t, mstore)
	fmt.Printf("%+v\n", gotGHSARecs[0])
	if diff := cmp.Diff(wantGHSARecs, gotGHSARecs,
		cmpopts.IgnoreFields(store.GHSARecord{}, "IssueCreatedAt")); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestNewCVEBody(t *testing.T) {
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

	rep := &report.Report{
		Modules: []*report.Module{{Module: "a.Module"}},
		CVEs:    []string{"ID1"},
		GHSAs:   []string{},
	}

	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	rc, err := report.NewTestClient(map[string]*report.Report{
		"data/reports/GO-9999-0002.yaml": rep,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := newCVEBody(r, rc, pc)
	if err != nil {
		t.Fatal(err)
	}
	want := `ID1 references [a.Module](https://a.Module), which may be a Go module.

Description:
a description

References:
- NIST: https://nvd.nist.gov/vuln/detail/ID1
- JSON: https://github.com/CVEProject/cvelist/tree//
- Imported by: https://pkg.go.dev/a.Module?tab=importedby

Cross references:
- ID1 appears in issue #2
- Module a.Module appears in issue #2


See [doc/triage.md](https://github.com/golang/vulndb/blob/master/doc/triage.md) for instructions on how to triage this report.

` + "```" + `
id: GO-ID-PENDING
modules:
    - module: a.Module
      packages:
        - package: a.Module
cves:
    - ID1

` + "```"
	if diff := cmp.Diff(unindent(want), got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestCreateGHSABody(t *testing.T) {
	r := &store.GHSARecord{
		GHSA: &ghsa.SecurityAdvisory{
			ID:          "G1",
			Identifiers: []ghsa.Identifier{{Type: "GHSA", Value: "G1"}},
			Permalink:   "https://github.com/permalink/to/G1",
			Description: "a description",
			Vulns: []*ghsa.Vuln{{
				Package:                "aPackage",
				EarliestFixedVersion:   "1.2.3",
				VulnerableVersionRange: "< 1.2.3",
			}},
		},
	}
	rep := &report.Report{
		Excluded: "EXCLUDED",
		GHSAs:    []string{"G1"},
	}

	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	rc, err := report.NewTestClient(map[string]*report.Report{
		"data/excluded/GO-9999-0001.yaml": rep,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := CreateGHSABody(r.GHSA, rc, pc)
	if err != nil {
		t.Fatal(err)
	}
	want := `In GitHub Security Advisory [G1](https://github.com/permalink/to/G1), there is a vulnerability in the following Go packages or modules:

| Unit | Fixed | Vulnerable Ranges |
| - | - | - |
| [aPackage](https://pkg.go.dev/aPackage) | 1.2.3 | < 1.2.3 |

Cross references:
- G1 appears in issue #1  EXCLUDED


See [doc/triage.md](https://github.com/golang/vulndb/blob/master/doc/triage.md) for instructions on how to triage this report.

` + "```" + `
modules:
    - module: aPackage
      versions:
        - fixed: 1.2.3
      packages:
        - package: aPackage
ghsas:
    - G1

` + "```"

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

func day(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}

func TestUpdateGHSAs(t *testing.T) {
	ctx := context.Background()
	sas := []*ghsa.SecurityAdvisory{
		{
			ID:        "g1",
			UpdatedAt: day(2021, 10, 1),
		},
		{
			ID:        "g2",
			UpdatedAt: day(2021, 11, 1),
		},
		{
			ID:        "g3",
			UpdatedAt: day(2021, 12, 1),
		},
		{
			ID:          "g4",
			Identifiers: []ghsa.Identifier{{Type: "CVE", Value: "CVE-2000-1111"}},
			UpdatedAt:   day(2021, 12, 1),
		},
		{
			ID:          "g5",
			Identifiers: []ghsa.Identifier{{Type: "CVE", Value: "CVE-2000-2222"}},
			UpdatedAt:   day(2021, 12, 1),
		},
	}

	mstore := store.NewMemStore()
	listSAs := fakeListFunc(sas)
	updateAndCheck := func(wantStats UpdateGHSAStats, wantRecords []*store.GHSARecord) {
		t.Helper()
		gotStats, err := UpdateGHSAs(ctx, listSAs, mstore)
		if err != nil {
			t.Fatal(err)
		}
		if gotStats != wantStats {
			t.Errorf("\ngot  %+v\nwant %+v", gotStats, wantStats)
		}
		gotRecords := getGHSARecordsSorted(t, mstore)
		if diff := cmp.Diff(wantRecords, gotRecords); diff != "" {
			t.Errorf("mismatch (-want, +got):\n%s", diff)
		}
	}

	// Add some existing CVE records.
	ctime := time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)
	crs := []*store.CVERecord{
		{
			ID:          "CVE-2000-1111",
			BlobHash:    "bh1",
			CommitHash:  "ch",
			CommitTime:  ctime,
			Path:        "path1",
			TriageState: store.TriageStateNoActionNeeded,
		},
		{
			ID:          "CVE-2000-2222",
			BlobHash:    "bh2",
			CommitHash:  "ch",
			CommitTime:  ctime,
			Path:        "path2",
			TriageState: store.TriageStateIssueCreated,
		},
	}
	createCVERecords(t, mstore, crs)

	// First four SAs entered with NeedsIssue.
	var want []*store.GHSARecord
	for _, sa := range sas[:4] {
		want = append(want, &store.GHSARecord{
			GHSA:        sa,
			TriageState: store.TriageStateNeedsIssue,
		})
	}
	// SA "g5" entered with Alias state because it is an alias of
	// "CVE-2000-2222" which already has an issue.
	want = append(want, &store.GHSARecord{
		GHSA:        sas[4],
		TriageState: store.TriageStateAlias,
	})
	updateAndCheck(UpdateGHSAStats{5, 5, 0}, want)

	// New SA added, old one updated.
	sas[0] = &ghsa.SecurityAdvisory{
		ID:        sas[0].ID,
		UpdatedAt: day(2021, 12, 2),
	}
	want[0].GHSA = sas[0]
	sas = append(sas, &ghsa.SecurityAdvisory{
		ID:        "g6",
		UpdatedAt: day(2021, 12, 2),
	})
	listSAs = fakeListFunc(sas)
	want = append(want, &store.GHSARecord{
		GHSA:        sas[len(sas)-1],
		TriageState: store.TriageStateNeedsIssue,
	})

	// Next update processes two SAs, modifies one and adds one.
	updateAndCheck(UpdateGHSAStats{2, 1, 1}, want)

}

func getGHSARecordsSorted(t *testing.T, st store.Store) []*store.GHSARecord {
	t.Helper()
	rs, err := getGHSARecords(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].GHSA.ID < rs[j].GHSA.ID })
	return rs
}

func fakeListFunc(sas []*ghsa.SecurityAdvisory) GHSAListFunc {
	return func(ctx context.Context, since time.Time) ([]*ghsa.SecurityAdvisory, error) {
		var rs []*ghsa.SecurityAdvisory
		for _, sa := range sas {
			if !sa.UpdatedAt.Before(since) {
				rs = append(rs, sa)
			}
		}
		return rs, nil
	}
}

func TestYearLabel(t *testing.T) {
	for _, test := range []struct {
		input, want string
	}{
		{"CVE-2022-24726", "cve-year-2022"},
		{"CVE-2021-24726", "cve-year-2021"},
		{"CVE-2020-24726", "cve-year-2020"},
		{"CVE-2019-9741", "cve-year-2019-and-earlier"},
		{"GHSA-p93v-m2r2-4387", ""},
	} {
		if got := yearLabel(test.input); got != test.want {
			t.Errorf("yearLabel(%q): %q; want = %q", test.input, got, test.want)
		}
	}
}
