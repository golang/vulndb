// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import (
	"bytes"
	"flag"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var update = flag.Bool("update", false, "update the data files based on the examples in data/examples.json")

func TestWriteCheckFiles(t *testing.T) {
	tmp := t.TempDir()
	es := Examples{
		{
			Input: Input{
				Module:      "foo",
				Description: "a description",
			},
			Suggestion: Suggestion{
				Summary:     "an issue with foo",
				Description: "a description of the issue with foo",
			},
		},
		{
			Input: Input{
				Module:      "bar",
				Description: "something about bar",
			},
			Suggestion: Suggestion{
				Summary:     "bad bar",
				Description: "something more about bar containing `backticks` and \"quotes\"",
			},
		},
	}

	if err := es.WriteFiles(tmp); err != nil {
		t.Fatalf("WriteFiles err = %v", err)
	}
	if err := checkFiles(tmp, 2); err != nil {
		t.Fatalf("CheckFiles err = %v", err)
	}
	wantErr := "fewer than 3 examples"
	if err := checkFiles(tmp, 3); err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("CheckFiles err = %v, want err containing %q", err, wantErr)
	}
}

func TestCheckRealFiles(t *testing.T) {
	folder := "."
	if err := checkFiles(folder, defaultMaxExamples); err != nil {
		if *update {
			// If the .json file is valid, use it as a source of truth to update
			// the other files.
			es, err := readFile(filepath.Join(folder, dataFolder, jsonFile))
			if err != nil {
				t.Fatalf("could not update files: could not read %q: %v", jsonFile, err)
			}
			if err := es.WriteFiles(folder); err != nil {
				t.Fatalf("could not update files: %v", err)
			}
			if err := checkFiles(folder, defaultMaxExamples); err != nil {
				t.Fatalf("files still invalid after update: %v", err)
			}
			return
		}
		t.Fatal(err)
	}
}

func TestWriteCSV(t *testing.T) {
	tests := []struct {
		name     string
		examples Examples
		want     string
	}{
		{
			name:     "empty",
			examples: Examples{},
			want:     "",
		},
		{
			name: "one example",
			examples: Examples{
				{
					Input: Input{
						Module:      "foo",
						Description: "a description",
					},
					Suggestion: Suggestion{
						Summary:     "an issue with foo",
						Description: "a description of the issue with foo",
					},
				},
			},
			want: "\"{\"\"Module\"\":\"\"foo\"\",\"\"Description\"\":\"\"a description\"\"}\",\"{\"\"Summary\"\":\"\"an issue with foo\"\",\"\"Description\"\":\"\"a description of the issue with foo\"\"}\"\n",
		},
		{
			name: "multiple examples",
			examples: Examples{
				{
					Input: Input{
						Module:      "foo",
						Description: "a description",
					},
					Suggestion: Suggestion{
						Summary:     "an issue with foo",
						Description: "a description of the issue with foo",
					},
				},
				{
					Input: Input{
						Module:      "bar",
						Description: "something about bar",
					},
					Suggestion: Suggestion{
						Summary:     "bad bar",
						Description: "something more about bar containing `backticks` and \"quotes\"",
					},
				},
			},
			want: "\"{\"\"Module\"\":\"\"foo\"\",\"\"Description\"\":\"\"a description\"\"}\",\"{\"\"Summary\"\":\"\"an issue with foo\"\",\"\"Description\"\":\"\"a description of the issue with foo\"\"}\"\n\"{\"\"Module\"\":\"\"bar\"\",\"\"Description\"\":\"\"something about bar\"\"}\",\"{\"\"Summary\"\":\"\"bad bar\"\",\"\"Description\"\":\"\"something more about bar containing `backticks` and \\\"\"quotes\\\"\"\"\"}\"\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			if err := test.examples.writeCSV(w); err != nil {
				t.Fatalf("WriteCSV: %v", err)
			}
			if got := w.String(); got != test.want {
				t.Errorf("WriteCSV: got %q, want %q", got, test.want)
			}
		})
	}
}

func TestReadWriteJSON(t *testing.T) {
	tests := []struct {
		name       string
		examples   Examples
		jsonString string
	}{
		{
			name:       "empty",
			examples:   Examples{},
			jsonString: "[]\n",
		},
		{
			name: "one example",
			examples: Examples{
				{
					Input: Input{
						Module:      "foo",
						Description: "a description",
					},
					Suggestion: Suggestion{
						Summary:     "an issue with foo",
						Description: "a description of the issue with foo",
					},
				},
			},
			jsonString: "[{\"Input\":{\"Module\":\"foo\",\"Description\":\"a description\"},\"Suggestion\":{\"Summary\":\"an issue with foo\",\"Description\":\"a description of the issue with foo\"}}]\n",
		},
		{
			name: "multiple examples",
			examples: Examples{
				{
					Input: Input{
						Module:      "foo",
						Description: "a description",
					},
					Suggestion: Suggestion{
						Summary:     "an issue with foo",
						Description: "a description of the issue with foo",
					},
				},
				{
					Input: Input{
						Module:      "bar",
						Description: "something about bar",
					},
					Suggestion: Suggestion{
						Summary:     "bad bar",
						Description: "something more about bar containing `backticks` and \"quotes\"",
					},
				},
			},
			jsonString: "[{\"Input\":{\"Module\":\"foo\",\"Description\":\"a description\"},\"Suggestion\":{\"Summary\":\"an issue with foo\",\"Description\":\"a description of the issue with foo\"}},{\"Input\":{\"Module\":\"bar\",\"Description\":\"something about bar\"},\"Suggestion\":{\"Summary\":\"bad bar\",\"Description\":\"something more about bar containing `backticks` and \\\"quotes\\\"\"}}]\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			if err := test.examples.writeJSON(w); err != nil {
				t.Fatalf("WriteJSON: %v", err)
			}
			if got := w.String(); got != test.jsonString {
				t.Errorf("WriteJSON: got %q, want %q", got, test.jsonString)
			}

			r := strings.NewReader(test.jsonString)
			var got Examples
			if err := got.ReadJSON(r); err != nil {
				t.Fatalf("ReadJSON() %v", err)
			}
			if diff := cmp.Diff(test.examples, got); diff != "" {
				t.Errorf("ReadJSON() unexpected diff (-want,+got):\n%s", diff)
			}
		})
	}
}
