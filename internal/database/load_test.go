// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLoad(t *testing.T) {
	tmp := t.TempDir()
	gzip := true
	if err := txtarToDir(validTxtar, tmp, gzip); err != nil {
		t.Fatal(err)
	}

	got, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}

	want := valid
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load: unexpected diff (-want, +got):\n%v", diff)
	}
}

func TestLoadError(t *testing.T) {
	tests := []struct {
		name      string
		db        string
		gzip      bool
		wantErrRe string
	}{
		{
			name:      "invalid db.json",
			db:        invalidDBMetaTxtar,
			gzip:      true,
			wantErrRe: `db\.json: contents do not match`,
		},
		{
			name:      "invalid modules.json",
			db:        invalidModulesTxtar,
			gzip:      true,
			wantErrRe: `modules\.json: contents do not match`,
		},
		{
			name:      "invalid vulns.json",
			db:        invalidVulnsTxtar,
			gzip:      true,
			wantErrRe: `vulns\.json: contents do not match`,
		},
		{
			name:      "invalid entry filename",
			db:        invalidFilenameTxtar,
			gzip:      true,
			wantErrRe: `GO-1999-0001\.json:.*(cannot find|no such)`,
		},
		{
			name:      "unmarshalable entry contents",
			db:        invalidEntriesTxtar,
			gzip:      true,
			wantErrRe: `cannot unmarshal`,
		},
		{
			name:      "no gzip",
			db:        validTxtar,
			gzip:      false,
			wantErrRe: `\.gz:.*(cannot find|no such)`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmp := t.TempDir()
			if err := txtarToDir(test.db, tmp, test.gzip); err != nil {
				t.Fatal(err)
			}

			errRe := regexp.MustCompile(test.wantErrRe)
			if _, gotErr := Load(tmp); gotErr == nil ||
				!errRe.MatchString(gotErr.Error()) {
				t.Errorf("Load: got %s, want error containing %q", gotErr, test.wantErrRe)
			}
		})
	}
}

func TestRawLoad(t *testing.T) {
	tmp := t.TempDir()
	gzip := false
	if err := txtarToDir(validTxtar, tmp, gzip); err != nil {
		t.Fatal(err)
	}

	got, err := RawLoad(filepath.Join(tmp, idDir))
	if err != nil {
		t.Fatal(err)
	}

	want := valid
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load: unexpected diff (-want, +got):\n%v", diff)
	}
}
