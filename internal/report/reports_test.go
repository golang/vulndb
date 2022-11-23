// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/gitrepo"
)

var (
	r1 = Report{
		Modules: []*Module{
			{Module: "std"},
		},
		CVEMetadata: &CVEMeta{
			ID: "CVE-9999-0001",
		},
	}
	r2 = Report{
		Modules: []*Module{
			{Module: "example.com/fake/module"},
		},
		CVEMetadata: &CVEMeta{
			ID: "CVE-9999-0002",
		},
	}
	r4 = Report{
		Modules: []*Module{
			{Module: "example.com/another/module"},
		},

		GHSAs: []string{
			"GHSA-9999-abcd-efgh",
		},
	}
	r5 = Report{
		Modules: []*Module{
			{Module: "example.com/adiff/module"},
		},
		CVEs: []string{"CVE-9999-0002"},
	}
)

func TestGetAllExisting(t *testing.T) {

	wantByIssue := map[int]*Report{1: &r1, 2: &r2, 4: &r4, 5: &r5}
	wantByFile := map[string]*Report{
		"data/reports/GO-9999-0001.yaml":  &r1,
		"data/excluded/GO-9999-0002.yaml": &r2,
		"data/reports/GO-9999-0004.yaml":  &r4,
		"data/reports/GO-9999-0005.yaml":  &r5,
	}

	repo, err := gitrepo.ReadTxtarRepo("testdata/repo.txtar", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	gotByIssue, gotByFile, err := GetAllExisting(repo)
	if err != nil {
		t.Fatalf("GetAllExisting() error = %v, ", err)
	}
	if diff := cmp.Diff(gotByIssue, wantByIssue); diff != "" {
		t.Errorf("GetAllExisting(): byIssue mismatch (-got, +want): %s", diff)
	}

	if diff := cmp.Diff(gotByFile, wantByFile); diff != "" {
		t.Errorf("GetAllExisting() byFile mismatch (-got, +want): %s", diff)
	}
}
