// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/gitrepo"
)

var (
	fname1 = "data/reports/GO-9999-0001.yaml"
	r1     = Report{
		ID: "GO-9999-0001",
		Modules: []*Module{
			{Module: "std"},
		},
		CVEMetadata: &CVEMeta{
			ID: "CVE-9999-0001",
		},
	}
	fname2 = "data/excluded/GO-9999-0002.yaml"
	r2     = Report{
		ID: "GO-9999-0002",
		Modules: []*Module{
			{Module: "example.com/fake/module"},
		},
		CVEMetadata: &CVEMeta{
			ID: "CVE-9999-0002",
		},
		Excluded: "EFFECTIVELY_PRIVATE",
	}
	fname4 = "data/reports/GO-9999-0004.yaml"
	r4     = Report{
		ID: "GO-9999-0004",
		Modules: []*Module{
			{Module: "example.com/another/module"},
		},

		GHSAs: []string{
			"GHSA-9999-abcd-efgh",
		},
	}
	fname5 = "data/reports/GO-9999-0005.yaml"
	r5     = Report{
		ID: "GO-9999-0005",
		Modules: []*Module{
			{Module: "example.com/adiff/module"},
		},
		CVEs: []string{"CVE-9999-0005"},
	}

	txtarFile = filepath.Join("testdata", "repo.txtar")
)

func TestList(t *testing.T) {
	repo, err := gitrepo.ReadTxtarRepo(txtarFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rc, err := NewClient(repo)
	if err != nil {
		t.Fatal(err)
	}

	got := rc.List()
	want := []*Report{&r1, &r2, &r4, &r5}
	byID := func(a, b *Report) bool { return a.ID < b.ID }
	if diff := cmp.Diff(got, want, cmpopts.SortSlices(byID)); diff != "" {
		t.Errorf("mismatch (-got, +want): %s", diff)
	}
}

func TestXRef(t *testing.T) {
	repo, err := gitrepo.ReadTxtarRepo(txtarFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rc, err := NewClient(repo)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		r           *Report
		wantMatches map[string][]string
	}{
		{
			name: "No matches",
			r: &Report{
				Modules: []*Module{
					{Module: "example.com/unused/module"},
				},
				CVEMetadata: &CVEMeta{
					ID: "CVE-9999-0003",
				},
			},
			wantMatches: map[string][]string{},
		},
		{
			name: "Ignores std lib modules",
			r: &Report{
				Modules: []*Module{
					{Module: "std"},
				},
				CVEs: []string{"CVE-9999-0003"},
			},
			wantMatches: map[string][]string{},
		},
		{
			name: "Match on CVE (ignores std module)",
			r: &Report{
				Modules: []*Module{
					{Module: "std"},
				},
				CVEs: []string{"CVE-9999-0001"},
			},
			wantMatches: map[string][]string{
				fname1: {"CVE-9999-0001"},
			},
		},
		{
			name: "Match on GHSA & module",
			r:    &r4,
			wantMatches: map[string][]string{
				fname4: {
					"GHSA-9999-abcd-efgh",
					"Module example.com/another/module",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatches := rc.XRef(tt.r)
			if diff := cmp.Diff(gotMatches, tt.wantMatches); diff != "" {
				t.Errorf("XRef(): matches mismatch (-got, +want): %s", diff)
			}
		})
	}
}

func TestReportsByAliases(t *testing.T) {
	repo, err := gitrepo.ReadTxtarRepo(txtarFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rc, err := NewClient(repo)
	if err != nil {
		t.Fatal(err)
	}
	got := rc.ReportsByAlias("CVE-9999-0001")
	want := []*Report{&r1}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ReportsByAliases() mismatch (-want, +got): %s", diff)
	}
}

func TestAliasHasReport(t *testing.T) {
	repo, err := gitrepo.ReadTxtarRepo(txtarFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rc, err := NewClient(repo)
	if err != nil {
		t.Fatal(err)
	}
	id := "CVE-9999-0001"
	got := rc.AliasHasReport("CVE-9999-0001")
	want := true

	if got != want {
		t.Errorf("AliasHasReport(%s) = %t, want %t", id, got, want)
	}
}

func TestNewClient(t *testing.T) {
	// Test that NewClient and NewTestClient have the same behavior.
	repo, err := gitrepo.ReadTxtarRepo(txtarFile, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(repo)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string]*Report{
		fname1: &r1, fname2: &r2, fname4: &r4, fname5: &r5,
	}
	tc, err := NewTestClient(files)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(c, tc, cmp.AllowUnexported(Client{})); diff != "" {
		t.Errorf("NewClient() / NewTestClient() mismatch (-New, +NewTest): %s", diff)
	}
}
