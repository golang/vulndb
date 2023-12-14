// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cveutils

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/tools/txtar"
	"golang.org/x/vulndb/internal/test"
)

func TestList(t *testing.T) {
	realDeltaLog, err := readFileFromArchive(deltaLogTxtar, "cves/deltaLog.json")
	if err != nil {
		t.Fatal(err)
	}
	simple := simpleDeltaLog()

	tcs := []struct {
		name     string
		since    string
		deltaLog []byte
		want     []string
	}{
		{
			// If the "since" time is after the latest fetch time,
			// no CVEs are found.
			name:     "since>latest",
			since:    jan7,
			deltaLog: simple,
			want:     nil,
		},
		{
			// If the "since" time is equal to the earliest fetch time,
			// all CVEs in the log are looked at (but not necessarily returned).
			// In this case, cve1 is not returned because it was
			// updated before the "since" time.
			// cve4 was added and updated, but only appears once.
			name:     "since=earliest",
			since:    jan2,
			deltaLog: simple,
			want:     []string{cve2, cve3, cve4, cve5},
		},
		{
			// cve1 and and cve2 don't make the cutoff.
			name:     "latest>since>earliest",
			since:    jan3,
			deltaLog: simple,
			want:     []string{cve3, cve4, cve5},
		},
		{
			name:     "real log",
			since:    "2023-12-13T17:54:14.241Z",
			deltaLog: realDeltaLog.Data,
			want: []string{
				"CVE-2023-43813",
				"CVE-2023-46726",
				"CVE-2023-6795",
				"CVE-2023-6790",
				"CVE-2023-6792",
				"CVE-2023-6794",
				"CVE-2023-6767",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s, c := newTestClientAndServer(t, tc.deltaLog)
			t.Cleanup(s.Close)
			since := mustParse(tc.since)

			got, err := list(c, s.URL, since)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.want, got,
				// Ignore order.
				cmpopts.SortSlices(func(x, y string) bool { return x < y })); diff != "" {
				t.Errorf("list(%s) mismatch (-want, +got):\n%s", tc.since, diff)
			}
		})
	}
}

func TestListFail(t *testing.T) {
	realDeltaLog, err := readFileFromArchive(deltaLogTxtar, "cves/deltaLog.json")
	if err != nil {
		t.Fatal(err)
	}

	tcs := []struct {
		name     string
		since    string
		deltaLog []byte
		wantErr  error
	}{
		{
			name:     "simple",
			since:    jan1,
			deltaLog: simpleDeltaLog(),
			wantErr:  errSinceTooEarly,
		},
		{
			name:     "real log",
			since:    "2023-11-13T19:25:22.000Z", // right before earliest fetch time
			deltaLog: realDeltaLog.Data,
			wantErr:  errSinceTooEarly,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s, c := newTestClientAndServer(t, realDeltaLog.Data)
			t.Cleanup(s.Close)
			since := mustParse(tc.since)
			_, err := list(c, s.URL, since)
			if !errors.Is(err, errSinceTooEarly) {
				t.Errorf("list() = %s, want error", errSinceTooEarly)
			}
		})
	}
}

// A txtar archive containing an actual delta log pulled from cvelistV5.
var deltaLogTxtar = filepath.Join("testdata", "deltaLog.txtar")

const (
	jan7     = "2000-01-07T00:00:00.000Z"
	jan6     = "2000-01-06T00:00:00.000Z"
	jan5Noon = "2000-01-05T12:00:00.000Z"
	jan5     = "2000-01-05T00:00:00.000Z"
	jan4Noon = "2000-01-04T12:00:00.000Z"
	jan4     = "2000-01-04T00:00:00.000Z"
	jan3Noon = "2000-01-03T12:00:00.000Z"
	jan3     = "2000-01-03T00:00:00.000Z"
	jan2     = "2000-01-02T00:00:00.000Z"
	jan1     = "2000-01-01T00:00:00.000Z"

	cve5 = "CVE-2000-0005"
	cve4 = "CVE-2000-0004"
	cve3 = "CVE-2000-0003"
	cve2 = "CVE-2000-0002"
	cve1 = "CVE-2000-0001"
)

// simpleDeltaLog returns a delta log with fake data for testing.
func simpleDeltaLog() []byte {
	dl := []*updateMeta{
		{
			FetchTime: jan6,
			New: []*cveMeta{
				{
					ID:      cve5,
					Updated: jan5Noon,
				},
			},
			Updated: []*cveMeta{
				{
					ID:      cve4,
					Updated: jan4Noon,
				},
			},
		},
		{
			FetchTime: jan4,
			New: []*cveMeta{
				{
					ID:      cve4,
					Updated: jan4,
				},
			},
			Updated: []*cveMeta{
				{
					ID:      cve3,
					Updated: jan3Noon,
				},
				// It's possible for the "updated" time to be before
				// the next "fetch" time, because of an inconsistency in
				// the way "fetch" and "updated" are calculated.
				// See the comment on the cveMeta.Updated for more info.
				{
					ID:      cve1,
					Updated: jan1,
				},
			},
		},
		{
			FetchTime: jan2,
			New: []*cveMeta{
				{
					ID:      cve2,
					Updated: jan2,
				},
			},
			Updated: []*cveMeta{},
		},
	}
	b, err := json.Marshal(dl)
	if err != nil {
		panic(err)
	}
	return b
}

func readFileFromArchive(filename, fileInArchive string) (*txtar.File, error) {
	ar, err := txtar.ParseFile(filename)
	if err != nil {
		return nil, err
	}
	return test.FindFile(ar, fileInArchive)
}

func newTestClientAndServer(t *testing.T, b []byte) (*httptest.Server, *http.Client) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(b)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			t.Errorf("could not write response body: %v", err)
		}
	}))
	c := s.Client()
	return s, c
}

func mustParse(s string) time.Time {
	t, err := parseTime(s)
	if err != nil {
		panic(err)
	}
	return t
}
