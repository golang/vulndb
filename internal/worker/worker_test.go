// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17

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
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/gitrepo"
	"golang.org/x/vulndb/internal/issues"
	"golang.org/x/vulndb/internal/issues/githubtest"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/worker/store"
)

const testRepoPath = "testdata/basic.txtar"

var (
	realProxy = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")

	testTime = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
)

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

var (
	ghsa1, ghsa2, ghsa3, ghsa4, ghsa5, ghsa6 = "GHSA-xxxx-yyyy-1111", "GHSA-xxxx-yyyy-2222", "GHSA-xxxx-yyyy-3333", "GHSA-xxxx-yyyy-4444", "GHSA-xxxx-yyyy-5555", "GHSA-xxxx-yyyy-6666"
)

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

	crs := []*store.CVE4Record{
		{
			ID:         "CVE-2000-0001",
			BlobHash:   "bh1",
			CommitHash: "ch",
			CommitTime: ctime,
			Path:       "path1",
			CVE: &cve4.CVE{
				Metadata: cve4.Metadata{
					ID: "CVE-2000-0001",
				},
			},
			TriageState: store.TriageStateNeedsIssue,
		},
		{
			ID:          "CVE-2000-0002",
			BlobHash:    "bh2",
			CommitHash:  "ch",
			CommitTime:  ctime,
			Path:        "path2",
			TriageState: store.TriageStateNoActionNeeded,
		},
		{
			ID:          "CVE-2000-0003",
			BlobHash:    "bh3",
			CommitHash:  "ch",
			CommitTime:  ctime,
			Path:        "path3",
			TriageState: store.TriageStateIssueCreated,
		},
	}
	createCVE4Records(t, mstore, crs)
	grs := []*store.LegacyGHSARecord{
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    ghsa1,
				Vulns: []*ghsa.Vuln{{Package: "p1"}},
			},
			TriageState: store.TriageStateNeedsIssue,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    ghsa2,
				Vulns: []*ghsa.Vuln{{Package: "p2"}},
			},
			TriageState: store.TriageStateNoActionNeeded,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    ghsa3,
				Vulns: []*ghsa.Vuln{{Package: "p3"}},
			},
			TriageState: store.TriageStateIssueCreated,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:    ghsa4,
				Vulns: []*ghsa.Vuln{{Package: "p4"}},
			},
			TriageState: store.TriageStateAlias,
		},
		{
			GHSA: &ghsa.SecurityAdvisory{
				ID:          ghsa5,
				Vulns:       []*ghsa.Vuln{{Package: "p1"}},
				Identifiers: []ghsa.Identifier{{Type: "GHSA", Value: ghsa5}},
			},
			TriageState: store.TriageStateNeedsIssue,
		},
	}
	createLegacyGHSARecords(t, mstore, grs)

	// Add an existing report with GHSA "g5".
	rc, err := report.NewTestClient(map[string]*report.Report{
		"data/reports/GO-1999-0001.yaml": {GHSAs: []string{ghsa5}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := CreateIssues(ctx, mstore, ic, pc, rc, 0); err != nil {
		t.Fatal(err)
	}

	var wantCVE4Records []*store.CVE4Record
	for _, r := range crs {
		copy := *r
		wantCVE4Records = append(wantCVE4Records, &copy)
	}
	wantCVE4Records[0].TriageState = store.TriageStateIssueCreated
	wantCVE4Records[0].IssueReference = "https://github.com/test-owner/test-repo/issues/1"

	gotCVERecs := mstore.CVE4Records()
	if len(gotCVERecs) != len(wantCVE4Records) {
		t.Fatalf("wrong number of records: got %d, want %d", len(gotCVERecs), len(wantCVE4Records))
	}
	for _, want := range wantCVE4Records {
		got := gotCVERecs[want.ID]
		if !cmp.Equal(got, want, cmpopts.IgnoreFields(store.CVE4Record{}, "IssueCreatedAt")) {
			t.Errorf("\ngot  %+v\nwant %+v", got, want)
		}
	}

	var wantGHSARecs []*store.LegacyGHSARecord
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
		cmpopts.IgnoreFields(store.LegacyGHSARecord{}, "IssueCreatedAt")); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestNewCVEBody(t *testing.T) {
	cr := &store.CVE4Record{
		ID:     "CVE-2000-0001",
		Module: "golang.org/x/vulndb",
		CVE: &cve4.CVE{
			Metadata: cve4.Metadata{
				ID: "CVE-2000-0001",
			},
			Description: cve4.Description{
				Data: []cve4.LangString{{
					Lang:  "eng",
					Value: "a description",
				}},
			},
		},
	}

	xrefReport := &report.Report{
		Modules: []*report.Module{{Module: "golang.org/x/vulndb"}},
		CVEs:    []string{"CVE-2000-0001"},
		GHSAs:   []string{},
	}

	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	r := report.New(cr.CVE, pc, report.WithCreated(testTime), report.WithModulePath(cr.Module))

	rc, err := report.NewTestClient(map[string]*report.Report{
		"data/reports/GO-9999-0002.yaml": xrefReport,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := NewIssueBody(r, cr.GetDescription(), rc)
	if err != nil {
		t.Fatal(err)
	}
	want := `Advisory [CVE-2000-0001](https://nvd.nist.gov/vuln/detail/CVE-2000-0001) references a vulnerability in the following Go modules:

| Module |
| - |
| [golang.org/x/vulndb](https://pkg.go.dev/golang.org/x/vulndb) |

Description:
a description

References:
- ADVISORY: https://nvd.nist.gov/vuln/detail/CVE-2000-0001

!! Possible duplicate report !!
- CVE-2000-0001 appears in 1 other report(s):
  - data/reports/GO-9999-0002.yaml    (https://github.com/golang/vulndb/issues/2)

Cross references:
- golang.org/x/vulndb appears in 1 other report(s):
  - data/reports/GO-9999-0002.yaml    (https://github.com/golang/vulndb/issues/2)

See [doc/quickstart.md](https://github.com/golang/vulndb/blob/master/doc/quickstart.md) for instructions on how to triage this report.

` + "```" + `
id: GO-ID-PENDING
modules:
    - module: golang.org/x/vulndb
      vulnerable_at: 0.0.0-20240515211212-610562879ffa
summary: CVE-2000-0001 in golang.org/x/vulndb
cves:
    - CVE-2000-0001
references:
    - advisory: https://nvd.nist.gov/vuln/detail/CVE-2000-0001
source:
    id: CVE-2000-0001
    created: 1999-01-01T00:00:00Z
review_status: UNREVIEWED

` + "```"
	if diff := cmp.Diff(unindent(want), got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
		t.Errorf("got: %s", got)
	}
}

func TestCreateGHSABody(t *testing.T) {
	gr := &store.LegacyGHSARecord{
		GHSA: &ghsa.SecurityAdvisory{
			ID:          "GHSA-xxxx-yyyy-zzzz",
			Identifiers: []ghsa.Identifier{{Type: "GHSA", Value: "GHSA-xxxx-yyyy-zzzz"}},
			Description: "a description",
			Vulns: []*ghsa.Vuln{{
				Package:                "golang.org/x/tools",
				EarliestFixedVersion:   "0.21.0",
				VulnerableVersionRange: "< 0.21.0",
			}},
			References: []ghsa.Reference{
				{URL: "https://example.com/commit/12345"},
			},
		},
	}
	rep := &report.Report{
		Excluded: "EXCLUDED",
		GHSAs:    []string{"GHSA-xxxx-yyyy-zzzz"},
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

	r := report.New(gr.GHSA, pc, report.WithCreated(testTime))
	got, err := NewIssueBody(r, gr.GetDescription(), rc)
	if err != nil {
		t.Fatal(err)
	}
	want := `Advisory [GHSA-xxxx-yyyy-zzzz](https://github.com/advisories/GHSA-xxxx-yyyy-zzzz) references a vulnerability in the following Go modules:

| Module |
| - |
| [golang.org/x/tools](https://pkg.go.dev/golang.org/x/tools) |

Description:
a description

References:
- ADVISORY: https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
- FIX: https://example.com/commit/12345

!! Possible duplicate report !!
- GHSA-xxxx-yyyy-zzzz appears in 1 other report(s):
  - data/excluded/GO-9999-0001.yaml    (https://github.com/golang/vulndb/issues/1)    EXCLUDED

See [doc/quickstart.md](https://github.com/golang/vulndb/blob/master/doc/quickstart.md) for instructions on how to triage this report.

` + "```" + `
id: GO-ID-PENDING
modules:
    - module: golang.org/x/tools
      versions:
        - fixed: 0.21.0
      vulnerable_at: 0.20.0
summary: GHSA-xxxx-yyyy-zzzz in golang.org/x/tools
ghsas:
    - GHSA-xxxx-yyyy-zzzz
references:
    - advisory: https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
    - fix: https://example.com/commit/12345
source:
    id: GHSA-xxxx-yyyy-zzzz
    created: 1999-01-01T00:00:00Z
review_status: UNREVIEWED

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
			ID:        ghsa1,
			UpdatedAt: day(2021, 10, 1),
		},
		{
			ID:        ghsa2,
			UpdatedAt: day(2021, 11, 1),
		},
		{
			ID:        ghsa3,
			UpdatedAt: day(2021, 12, 1),
		},
		{
			ID:          ghsa4,
			Identifiers: []ghsa.Identifier{{Type: "CVE", Value: "CVE-2000-1111"}},
			UpdatedAt:   day(2021, 12, 1),
		},
		{
			ID:          ghsa5,
			Identifiers: []ghsa.Identifier{{Type: "CVE", Value: "CVE-2000-2222"}},
			UpdatedAt:   day(2021, 12, 1),
		},
	}

	mstore := store.NewMemStore()
	listSAs := fakeListFunc(sas)
	updateAndCheck := func(wantStats UpdateGHSAStats, wantRecords []*store.LegacyGHSARecord) {
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
	crs := []*store.CVE4Record{
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
	createCVE4Records(t, mstore, crs)

	// First four SAs entered with NeedsIssue.
	var want []*store.LegacyGHSARecord
	for _, sa := range sas[:4] {
		want = append(want, &store.LegacyGHSARecord{
			GHSA:        sa,
			TriageState: store.TriageStateNeedsIssue,
		})
	}
	// SA "g5" entered with Alias state because it is an alias of
	// "CVE-2000-2222" which already has an issue.
	want = append(want, &store.LegacyGHSARecord{
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
		ID:        ghsa6,
		UpdatedAt: day(2021, 12, 2),
	})
	listSAs = fakeListFunc(sas)
	want = append(want, &store.LegacyGHSARecord{
		GHSA:        sas[len(sas)-1],
		TriageState: store.TriageStateNeedsIssue,
	})

	// Next update processes two SAs, modifies one and adds one.
	updateAndCheck(UpdateGHSAStats{2, 1, 1}, want)

}

func getGHSARecordsSorted(t *testing.T, st store.Store) []*store.LegacyGHSARecord {
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
