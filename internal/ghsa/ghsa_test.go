// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ghsa

import (
	"context"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var githubTokenFile = flag.String("ghtokenfile", "",
	"path to file containing GitHub access token")

func mustGetAccessToken(t *testing.T) string {
	if *githubTokenFile == "" {
		t.Skip("-ghtokenfile not provided")
	}
	bytes, err := os.ReadFile(*githubTokenFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(bytes))
}

func TestList(t *testing.T) {
	accessToken := mustGetAccessToken(t)
	// There were at least three relevant SAs since this date.
	since := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	const withoutCVEs = false
	got, err := List(context.Background(), accessToken, since, withoutCVEs)
	if err != nil {
		t.Fatal(err)
	}
	want := 3
	if len(got) < want {
		t.Errorf("got %d, want at least %d", len(got), want)
	}
	for _, g := range got {
		if isCVE(g.Identifiers) {
			t.Errorf("isCVE true, want false for %+v", g)
		}
	}
}

func TestFetchGHSA(t *testing.T) {
	accessToken := mustGetAccessToken(t)
	// Real GHSA that should be found.
	const ghsaID string = "GHSA-g9mp-8g3h-3c5c"
	got, err := FetchGHSA(context.Background(), accessToken, ghsaID)
	if err != nil {
		t.Fatal(err)
	}
	want := ghsaID
	var gotID string
	for _, id := range got.Identifiers {
		if id.Type == "GHSA" {
			gotID = id.Value
			break
		}
	}
	if gotID != want {
		t.Errorf("got GHSA with id %q, want %q", got.ID, want)
	}
}

func TestListForCVE(t *testing.T) {
	accessToken := mustGetAccessToken(t)
	// Real CVE and GHSA.
	const (
		cveID  string = "CVE-2022-27191"
		ghsaID string = "GHSA-8c26-wmh5-6g9v"
	)
	got, err := ListForCVE(context.Background(), accessToken, cveID)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, sa := range got {
		for _, id := range sa.Identifiers {
			if id.Type != "GHSA" {
				continue
			}
			ids = append(ids, id.Value)
			if id.Value == ghsaID {
				return
			}
		}
	}
	t.Errorf("got %v GHSAs %v, want %v", len(got), ids, ghsaID)
}
