// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/cveschema"
	"golang.org/x/vulndb/internal/worker/store"
)

func TestInsertFalsePositives(t *testing.T) {
	mstore := store.NewMemStore()
	if err := InsertFalsePositives(context.Background(), mstore); err != nil {
		t.Fatal(err)
	}
	// Spot-check a couple of records.
	const commitHash = "17294f1a2af61a2a2df52ac89cbd7c516f0c4e6a"
	got := mstore.CVERecords()
	for _, want := range []*store.CVERecord{
		{
			ID:          "CVE-2016-0216",
			Path:        "2016/0xxx/CVE-2016-0216.json",
			CommitHash:  commitHash,
			BlobHash:    "ac9f59c6700576b5936dc014ce265ee0c9a41097",
			CVEState:    cveschema.StatePublic,
			TriageState: store.TriageStateFalsePositive,
			ReferenceURLs: []string{
				"http://www.ibm.com/support/docview.wss?uid=swg21975358",
				"http://www.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_multiple_security_vulnerabilities_in_ibm_tivoli_storage_manager_fastback_cve_2016_0212_cve_2016_0213_cve_2016_0216",
			},
		},
		{
			ID:                "CVE-2020-15112",
			Path:              "2020/15xxx/CVE-2020-15112.json",
			CommitHash:        commitHash,
			BlobHash:          "3d87891317ff107037bc0145194ab72df1890411",
			CVEState:          cveschema.StatePublic,
			TriageState:       store.TriageStateHasVuln,
			TriageStateReason: "GO-2020-0005",
		},
	} {
		if diff := cmp.Diff(want, got[want.ID]); diff != "" {
			t.Errorf("mismatch (-want, +got):\n%s", diff)
		}
	}
}
