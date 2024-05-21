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

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/cve4"
	"golang.org/x/vulndb/internal/worker/store"
)

func TestUpdateFalsePositives(t *testing.T) {
	const commitHash = "17294f1a2af61a2a2df52ac89cbd7c516f0c4e6a"
	commitTime := time.Date(2021, time.April, 12, 23, 0, 56, 0, time.UTC)

	mstore := store.NewMemStore()
	createCVE4Records(t, mstore, []*store.CVE4Record{
		// This DB record is older than the matching false positive record
		// embedded in the program, so it will be updated.
		{
			ID:                "CVE-2020-15112",
			Path:              "2020/15xxx/CVE-2020-15112.json",
			CommitHash:        "xyz",
			CommitTime:        time.Date(2021, time.March, 1, 0, 0, 0, 0, time.UTC),
			BlobHash:          "3d87891317ff107037bc0145194ab72df1890411",
			CVEState:          cve4.StatePublic,
			TriageState:       store.TriageStateNeedsIssue,
			TriageStateReason: "will be replaced",
		},
		// This DB record is newer, so it won't be changed.
		{
			ID:          "CVE-2020-15113",
			Path:        "2020/15xxx/CVE-2020-15113.json",
			BlobHash:    "9133c3be68ef84771bad74ec8770e1efff7bf0de",
			CommitHash:  commitHash,
			CommitTime:  commitTime,
			CVEState:    cve4.StatePublic,
			TriageState: store.TriageStateNoActionNeeded,
			ReferenceURLs: []string{
				"https://github.com/etcd-io/etcd/security/advisories/GHSA-chh6-ppwq-jh92",
			},
		},
	})

	if err := updateFalsePositives(context.Background(), mstore); err != nil {
		t.Fatal(err)
	}
	got := mstore.CVE4Records()
	for _, want := range []*store.CVE4Record{
		{
			// Doesn't exist in DB.
			ID:          "CVE-2016-0216",
			Path:        "2016/0xxx/CVE-2016-0216.json",
			CommitHash:  commitHash,
			CommitTime:  commitTime,
			BlobHash:    "ac9f59c6700576b5936dc014ce265ee0c9a41097",
			CVEState:    cve4.StatePublic,
			TriageState: store.TriageStateFalsePositive,
			ReferenceURLs: []string{
				"http://www.ibm.com/support/docview.wss?uid=swg21975358",
				"http://www.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_multiple_security_vulnerabilities_in_ibm_tivoli_storage_manager_fastback_cve_2016_0212_cve_2016_0213_cve_2016_0216",
			},
		},
		{
			// Newer than DB.
			ID:                "CVE-2020-15112",
			Path:              "2020/15xxx/CVE-2020-15112.json",
			CommitHash:        commitHash,
			CommitTime:        commitTime,
			BlobHash:          "3d87891317ff107037bc0145194ab72df1890411",
			CVEState:          cve4.StatePublic,
			TriageState:       store.TriageStateHasVuln,
			TriageStateReason: "GO-2020-0005",
		},
		{
			ID:          "CVE-2020-15113",
			Path:        "2020/15xxx/CVE-2020-15113.json",
			BlobHash:    "9133c3be68ef84771bad74ec8770e1efff7bf0de",
			CommitHash:  commitHash,
			CommitTime:  commitTime,
			CVEState:    cve4.StatePublic,
			TriageState: store.TriageStateNoActionNeeded,
			ReferenceURLs: []string{
				"https://github.com/etcd-io/etcd/security/advisories/GHSA-chh6-ppwq-jh92",
			},
		},
	} {
		if diff := cmp.Diff(want, got[want.ID]); diff != "" {
			t.Errorf("mismatch (-want, +got):\n%s", diff)
		}
	}
}
