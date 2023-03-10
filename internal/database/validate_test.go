// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"strings"
	"testing"

	"golang.org/x/vuln/osv"
)

func TestValidate(t *testing.T) {
	small, big, invalid := t.TempDir(), t.TempDir(), t.TempDir()
	gzip := true
	if err := txtarToDir(smallTxtar, small, gzip); err != nil {
		t.Fatal(err)
	}
	if err := txtarToDir(validTxtar, big, gzip); err != nil {
		t.Fatal(err)
	}
	if err := txtarToDir(invalidModulesTxtar, invalid, gzip); err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		// Adding more entries is OK.
		if err := Validate(big, small); err != nil {
			t.Error(err)
		}
	})

	failTests := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "deleted entry",
			old:  big,
			new:  small,
		},
		{
			name: "invalid new db",
			old:  small,
			new:  invalid,
		},
		// TODO(tatianabradley): test invalid old db after first deploy.
	}
	for _, test := range failTests {
		t.Run(test.name, func(t *testing.T) {
			if err := Validate(test.new, test.old); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestValidateInternal(t *testing.T) {
	successTests := []struct {
		name string
		new  []osv.Entry
		old  []osv.Entry
	}{
		{
			name: "valid updates ok",
			old: []osv.Entry{{
				ID:        "GO-1999-0001",
				Published: jan1999,
				Modified:  jan1999,
			}},
			new: []osv.Entry{{
				ID:        "GO-1999-0001",
				Published: jan1999,
				Modified:  jan2000,
			}, {
				ID:        "GO-1999-0002",
				Published: jan2000,
				Modified:  jan2000,
			}},
		},
		{
			name: "same db ok",
			old: []osv.Entry{{
				ID:        "GO-1999-0001",
				Published: jan1999,
				Modified:  jan1999,
			}},
			new: []osv.Entry{{
				ID:        "GO-1999-0001",
				Published: jan1999,
				Modified:  jan1999,
			}},
		},
	}
	for _, test := range successTests {
		t.Run(test.name, func(t *testing.T) {
			new, err := New(test.new...)
			if err != nil {
				t.Fatal(err)
			}
			old, err := New(test.old...)
			if err != nil {
				t.Fatal(err)
			}
			if err := validate(new, old); err != nil {
				t.Errorf("validate(): unexpected error %v", err)
			}
		})
	}

	failTests := []struct {
		name    string
		new     []osv.Entry
		old     []osv.Entry
		wantErr string
	}{
		{
			name: "published time changed",
			old: []osv.Entry{
				{
					ID:        "GO-1999-0001",
					Published: jan1999,
					Modified:  jan1999,
				}},
			new: []osv.Entry{
				{
					ID:        "GO-1999-0001",
					Published: jan2000,
					Modified:  jan2000,
				},
			},
			wantErr: "published time cannot change",
		},
		{
			name: "deleted entry",
			old: []osv.Entry{
				{
					ID:        "GO-1999-0001",
					Published: jan1999,
					Modified:  jan1999,
				},
			},
			wantErr: "GO-1999-0001 is not present in new database",
		},
		{
			name: "modified time decreased",
			old: []osv.Entry{{
				ID:       "GO-1999-0001",
				Modified: jan2000,
			}},
			new: []osv.Entry{{
				ID:       "GO-1999-0001",
				Modified: jan1999,
			}},
			wantErr: "modified time cannot decrease",
		},
	}
	for _, test := range failTests {
		t.Run(test.name, func(t *testing.T) {
			new, err := New(test.new...)
			if err != nil {
				t.Fatal(err)
			}
			old, err := New(test.old...)
			if err != nil {
				t.Fatal(err)
			}
			if err := validate(new, old); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("validate(): want error containing %q, got %v", test.wantErr, err)
			}
		})
	}
}
