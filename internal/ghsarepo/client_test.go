// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ghsarepo

import (
	"flag"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/vulndb/internal/gitrepo"
)

var integration = flag.Bool("integration", false, "if true, access the real GHSA repo in tests")

func TestClientReal(t *testing.T) {
	if !*integration {
		t.Skipf("-integration flag not set")
	}
	c, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}

	// A real GHSA id and its corresponding CVE.
	ghsa, cve := "GHSA-8c26-wmh5-6g9v", "CVE-2022-27191"
	if osv := c.ByGHSA(ghsa); osv.ID != ghsa {
		t.Errorf("c.ByGHSA(%s).ID = %s, want %s", ghsa, osv.ID, ghsa)
	}
	if osvs := c.ByCVE(cve); osvs[0].ID != ghsa {
		t.Errorf("c.ByCVE(%s)[0].ID = %s, want %s", ghsa, osvs[0].ID, ghsa)
	}

	// A non-existent GHSA and CVE.
	notGHSA, notCVE := "GHSA-aaaa-bbbb-cccc", "CVE-0000-1111"
	if osv := c.ByGHSA(notGHSA); osv != nil {
		t.Errorf("c.ByGHSA(%s) = %v, want nil", ghsa, osv)
	}
	if osvs := c.ByCVE(notCVE); osvs != nil {
		t.Errorf("c.ByCVE(%s) = %v, want nil", ghsa, osvs)
	}
}

func TestByGHSA(t *testing.T) {
	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	// A GHSA id in the test repo.
	ghsa := "GHSA-abcd-efgh-b123"
	if osv := c.ByGHSA(ghsa); osv.ID != ghsa {
		t.Errorf("c.ByGHSA(%s).ID = %s, want %s", ghsa, osv.ID, ghsa)
	}

	// A GHSA not in the test repo.
	notGHSA := "GHSA-abcd-untouched"
	if osv := c.ByGHSA(notGHSA); osv != nil {
		t.Errorf("c.ByGHSA(%s) = %v, want nil", ghsa, osv)
	}
}

func TestByCVE(t *testing.T) {
	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	// A CVE in the test repo and its corresponding GHSA.
	cve, ghsa := "CVE-20YY-XXXX", "GHSA-abcd-efgh-b123"
	if osvs := c.ByCVE(cve); osvs[0].ID != ghsa {
		t.Errorf("c.ByCVE(%s)[0].ID = %s, want %s", ghsa, osvs[0].ID, ghsa)
	}

	// A CVE not in the test repo.
	notCVE := "CVE-0000-1111"
	if osvs := c.ByCVE(notCVE); osvs != nil {
		t.Errorf("c.ByCVE(%s) = %v, want nil", ghsa, osvs)
	}
}

func TestIDs(t *testing.T) {
	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"GHSA-abcd-efgh-b123", "GHSA-test-part-a123"}
	got := c.IDs()
	if diff := diffIgnoreOrder(want, got); diff != "" {
		t.Errorf("c.IDs() mismatch (-want +got)\n:%s", diff)
	}
}

func TestList(t *testing.T) {
	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	wantIDs := []string{"GHSA-abcd-efgh-b123", "GHSA-test-part-a123"}
	got := c.List()
	var gotIDs []string
	for _, osv := range got {
		gotIDs = append(gotIDs, osv.ID)
	}
	if diff := diffIgnoreOrder(wantIDs, gotIDs); diff != "" {
		t.Errorf("c.List() mismatch (-want +got)\n:%s", diff)
	}
}

func diffIgnoreOrder(s1, s2 []string) string {
	return cmp.Diff(s1, s2, cmpopts.SortSlices(func(a, b string) bool {
		return a < b
	}))
}

func newTestClient() (*Client, error) {
	repo, err := gitrepo.ReadTxtarRepo("testdata/repo.txtar", time.Now())
	if err != nil {
		return nil, err
	}
	return NewClientFromRepo(repo)
}
