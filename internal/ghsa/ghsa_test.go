// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ghsa

import (
	"context"
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var githubTokenFile = flag.String("ghtokenfile", "",
	"path to file containing GitHub access token")
var githubToken = flag.String("ghtoken", os.Getenv("VULN_GITHUB_ACCESS_TOKEN"), "GitHub access token")

func mustGetAccessToken(t *testing.T) string {
	var token string
	switch {
	case *githubToken != "":
		token = *githubToken
	case *githubTokenFile != "":
		bytes, err := os.ReadFile(*githubTokenFile)
		if err != nil {
			t.Fatal(err)
		}
		token = string(bytes)
	default:
		t.Skip("neither -ghtokenfile nor -ghtoken provided")
	}
	return strings.TrimSpace(string(token))
}

func setupClient(ctx context.Context, t *testing.T) *Client {
	t.Helper()
	accessToken := mustGetAccessToken(t)
	return NewClient(ctx, accessToken)
}

func TestList(t *testing.T) {
	ctx := context.Background()
	c := setupClient(ctx, t)
	// There were at least three relevant SAs since this date.
	since := time.Date(2022, 9, 1, 0, 0, 0, 0, time.UTC)
	got, err := c.List(context.Background(), since)
	if err != nil {
		t.Fatal(err)
	}
	want := 3
	if len(got) < want {
		t.Errorf("got %d, want at least %d", len(got), want)
	}
}

func TestFetchGHSA(t *testing.T) {
	ctx := context.Background()
	c := setupClient(ctx, t)
	// Real GHSA that should be found.
	const ghsaID string = "GHSA-g9mp-8g3h-3c5c"
	got, err := c.FetchGHSA(context.Background(), ghsaID)
	if err != nil {
		t.Fatal(err)
	}
	if gotID, want := got.ID, ghsaID; gotID != want {
		t.Errorf("got GHSA with id %q, want %q", got.ID, want)
	}
}

func TestListForCVE(t *testing.T) {
	ctx := context.Background()
	c := setupClient(ctx, t)
	tests := []struct {
		name string
		cve  string
		want []string
	}{
		{
			name: "Real CVE/GHSA",
			cve:  "CVE-2022-27191",
			want: []string{"GHSA-8c26-wmh5-6g9v"},
		},
		{
			name: "Check exact matching",
			cve:  "CVE-2022-2529",
			want: []string{"GHSA-9rpw-2h95-666c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.ListForCVE(ctx, tt.cve)
			if err != nil {
				t.Errorf("ListForCVE() error = %v", err)
				return
			}
			gotIDs := []string{}
			for _, sa := range got {
				gotIDs = append(gotIDs, sa.ID)
			}
			if !reflect.DeepEqual(gotIDs, tt.want) {
				t.Errorf("ListForCVE() = %v, want %v", gotIDs, tt.want)
			}
		})
	}
}
