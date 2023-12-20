// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSuggest(t *testing.T) {
	tests := []struct {
		name     string
		response *GenerateTextResponse
		want     []*Suggestion
	}{
		{
			name: "basic",
			response: &GenerateTextResponse{
				Candidates: []TextCompletion{
					{
						Output: `{"Summary":"summary","Description":"new description"}`,
					},
					{
						Output: `{"Summary":"another summary","Description":"another description"}`,
					},
				},
			},
			want: []*Suggestion{{
				Summary:     "summary",
				Description: "new description",
			},
				{
					Summary:     "another summary",
					Description: "another description",
				},
			},
		},
		{
			name: "ignore invalid",
			response: &GenerateTextResponse{
				Candidates: []TextCompletion{
					{
						Output: `{"Summary":"summary","Description":"new description"}`,
					},
					{
						Output: `invalid JSON ignored`,
					},
				},
			},
			want: []*Suggestion{
				{
					Summary:     "summary",
					Description: "new description",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt := "a prompt" // prompt doesn't matter since the response is hard-coded
			c, cleanup, err := testClient(generateTextEndpoint, prompt, tt.response)
			if err != nil {
				t.Fatalf("testClient() error = %v", err)
			}
			t.Cleanup(cleanup)
			got, err := c.suggest(prompt)
			if err != nil {
				t.Fatalf("suggest() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("suggest() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSuggestError(t *testing.T) {
	tests := []struct {
		name     string
		response *GenerateTextResponse
		wantErr  string
	}{
		{
			name:     "no response",
			response: nil,
			wantErr:  "no candidates",
		},
		{
			name: "unmarshal error",
			response: &GenerateTextResponse{
				Candidates: []TextCompletion{
					{
						Output: `Summary:"invalid",`,
					},
					{
						Output: `more invalid JSON`,
					},
				},
			},
			wantErr: `unmarshal`,
		},
		{
			name: "missing data",
			response: &GenerateTextResponse{
				Candidates: []TextCompletion{
					{
						// Valid JSON, but description is missing.
						Output: `{"Summary":"summary"}`,
					},
				},
			},
			wantErr: `empty summary or description`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt := "a prompt" // prompt doesn't matter since the response is hard-coded
			c, cleanup, gotErr := testClient(generateTextEndpoint, prompt, tt.response)
			if gotErr != nil {
				t.Fatalf("testClient() error = %v", gotErr)
			}
			t.Cleanup(cleanup)
			_, gotErr = c.suggest(prompt)
			if gotErr == nil || !strings.Contains(gotErr.Error(), tt.wantErr) {
				t.Fatalf("suggest() error = %v, want err containing %s", gotErr, tt.wantErr)
			}
		})
	}
}

func TestNewPrompt(t *testing.T) {
	type args struct {
		in            *Input
		promptContext string
		examples      Examples
		maxExamples   int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "basic",
			args: args{
				in: &Input{
					Module:      "input/module",
					Description: "original description of input",
				},
				promptContext: "Context for the prompt.",
				examples: Examples{
					&Example{
						Input: Input{
							Module:      "example/module",
							Description: "original description of example",
						},
						Suggestion: Suggestion{
							Summary:     "summary",
							Description: "new description",
						},
					},
				},
				maxExamples: 2, // no effect since there is only one example
			},
			want: `Context for the prompt.

input: {"Module":"example/module","Description":"original description of example"}
output: {"Summary":"summary","Description":"new description"}
input: {"Module":"input/module","Description":"original description of input"}
output:`,
		},
		{
			name: "trim examples",
			args: args{
				in: &Input{
					Module:      "input/module",
					Description: "original description of input",
				},
				promptContext: "Context",
				examples: Examples{
					&Example{
						Input: Input{
							Module:      "example/module",
							Description: "original description of example",
						},
						Suggestion: Suggestion{
							Summary:     "summary",
							Description: "new description",
						},
					},
					// This example will be ignored because maxExamples = 1.
					&Example{
						Input: Input{
							Module:      "another/example/module",
							Description: "original description of example 2",
						},
						Suggestion: Suggestion{
							Summary:     "summary 2",
							Description: "new description 2",
						},
					},
				},
				maxExamples: 1,
			},
			want: `Context

input: {"Module":"example/module","Description":"original description of example"}
output: {"Summary":"summary","Description":"new description"}
input: {"Module":"input/module","Description":"original description of input"}
output:`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newPrompt(tt.args.in, tt.args.promptContext, tt.args.examples, tt.args.maxExamples)
			if err != nil {
				t.Fatalf("newPrompt() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("newPrompt() = %v, want %v", got, tt.want)
			}
		})
	}
}
