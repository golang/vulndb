// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve4

import (
	"context"
	"flag"
	"testing"

	"golang.org/x/vulndb/internal/cvelistrepo"
)

var (
	updateTxtarRepo = flag.Bool("update-repo", false, "update the test repo (cvelist.txtar) with real CVE data - this takes a while")
	update          = flag.Bool("update", false, "update golden files")
	realProxy       = flag.Bool("proxy", false, "if true, contact the real module proxy and update expected responses")
)

func TestToReport(t *testing.T) {
	if *updateTxtarRepo {
		if err := cvelistrepo.UpdateTxtar(context.Background(), cvelistrepo.URLv4, cvelistrepo.TestCVEs); err != nil {
			t.Fatal(err)
		}
	}

	if err := cvelistrepo.TestToReport[*CVE](t, *update, *realProxy); err != nil {
		t.Fatal(err)
	}
}
