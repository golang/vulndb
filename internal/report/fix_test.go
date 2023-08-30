// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vulndb/internal/proxy"
)

func TestFix(t *testing.T) {
	r := Report{
		Modules: []*Module{
			{
				Module: "std",
				Versions: []VersionRange{
					{
						Introduced: "go1.20",
					},
					{
						Fixed: "go1.20.1",
					},
					{
						Introduced: "go1.19",
						Fixed:      "go1.19.5",
					},
					{
						Fixed: "go1.18.5",
					},
				},
				VulnerableAt: "go1.20",
			},
			{
				Module: "golang.org/x/vulndb",
				Versions: []VersionRange{{
					Introduced: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
				}},
				VulnerableAt: "0cbf4ffdb4e70fce663ec8d59198745b04e7801b",
			},
		},
		Description: "A long form description of the problem that will be broken up into multiple lines so it is more readable.",
		References: []*Reference{
			{
				URL: "https://github.com/golang/go/issues/123",
			},
		},
	}
	want := Report{
		Modules: []*Module{
			{
				Module: "std",
				Versions: []VersionRange{
					{
						Fixed: "1.18.5",
					},
					{
						Introduced: "1.19.0",
						Fixed:      "1.19.5",
					},
					{
						Introduced: "1.20.0",
						Fixed:      "1.20.1",
					},
				},
				VulnerableAt: "1.20.0",
			},
			{
				Module: "golang.org/x/vulndb",
				Versions: []VersionRange{{
					Introduced: "0.0.0-20230522180520-0cbf4ffdb4e7",
				}},
				VulnerableAt: "0.0.0-20230522180520-0cbf4ffdb4e7",
			},
		},
		Description: "A long form description of the problem that will be broken up into multiple\nlines so it is more readable.",
		References: []*Reference{
			{
				URL: "https://go.dev/issue/123",
			},
		},
	}

	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}

	r.Fix(pc)

	got := r
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Fix() mismatch (-want +got):\n%s", diff)
	}
}

func TestFixLineLength(t *testing.T) {
	tcs := []struct {
		name    string
		n       int
		unfixed string
		want    string
	}{
		{
			name:    "empty",
			n:       1,
			unfixed: "",
			want:    "",
		},
		{
			name: "multiple paragraphs with long lines",
			n:    80,
			unfixed: `Incorrect access control is possible in the go command.

The go command can misinterpret branch names that falsely appear to be version tags.
This can lead to incorrect access control if an actor is authorized to create branches
but not tags.`,
			want: `Incorrect access control is possible in the go command.

The go command can misinterpret branch names that falsely appear to be version
tags. This can lead to incorrect access control if an actor is authorized to
create branches but not tags.`,
		},
		{
			name:    "one paragraph",
			n:       15,
			unfixed: "A single paragraph description.",
			want:    "A single\nparagraph\ndescription.",
		},
		{
			name:    "word longer than max",
			n:       10,
			unfixed: "A single verylongword on its own line is OK",
			want:    "A single\nverylongword\non its own\nline is OK",
		},
		{
			name:    "word longer than max with paragraph",
			n:       10,
			unfixed: "A single\n\nverylongword\n\non its own",
			want:    "A single\n\nverylongword\n\non its own",
		},
		{
			name:    "ok - exactly at max",
			n:       19,
			unfixed: "This is already OK.\nThis is already OK.",
			want:    "This is already OK.\nThis is already OK.",
		},
		{
			name:    "ok - shorter than max",
			n:       20,
			unfixed: "This is already OK.",
			want:    "This is already OK.",
		},
		{
			name: "markdown",
			n:    20,
			unfixed: `Hello

1. this is a point
2. this is a longer point that will be broken up
3. this is point 3`,
			want: `Hello

1. this is a point
2. this is a longer
point that will be
broken up
3. this is point 3`,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := fixLineLength(tc.unfixed, tc.n)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("fixLineLength() mismatch (-want +got):\n%s\n%s", diff, got)
			}
		})
	}
}

func TestGuessVulnerableAt(t *testing.T) {
	pc, err := proxy.NewTestClient(t, *realProxy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		m    *Module
		want string
	}{
		{
			name: "no fix",
			m: &Module{
				Module: "golang.org/x/tools",
			},
			want: "0.12.0", // latest
		},
		{
			name: "has fix",
			m: &Module{
				Module: "golang.org/x/tools",
				Versions: []VersionRange{
					{
						Fixed: "0.1.8",
					},
				},
			},
			want: "0.1.7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.m.guessVulnerableAt(pc)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("guessVulnerableAt() = %q, want %s", got, tc.want)
			}
		})
	}
}
