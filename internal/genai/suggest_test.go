// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import (
	"context"
	"fmt"
	"strings"
	"testing"

	_ "embed"

	"github.com/google/go-cmp/cmp"
)

func TestSuggest(t *testing.T) {
	tests := []struct {
		name     string
		response []string
		want     []*Suggestion
	}{
		{
			name: "basic",
			response: []string{
				`{"Summary":"summary","Description":"new description"}`,
				`{"Summary":"another summary","Description":"another description"}`,
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
			response: []string{`{"Summary":"summary","Description":"new description"}`,
				`invalid JSON ignored`,
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
			// The input can be the same for each test because
			// the response is hard-coded.
			input := placeholderInput
			// Make sure Suggest calls defaultPrompt (or its equivalent).
			// A separate test checks that defaultPrompt is correct.
			c := &testCli{
				prompt:   mustGetDefaultPrompt(input),
				response: tt.response,
			}
			got, err := Suggest(context.Background(), c, input)
			if err != nil {
				t.Fatalf("Suggest() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Suggest() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGenSuggestionsError(t *testing.T) {
	tests := []struct {
		name     string
		response []string
		wantErr  string
	}{
		{
			name:     "no response",
			response: nil,
			wantErr:  "no candidates",
		},
		{
			name:     "unmarshal error",
			response: []string{`Summary:"invalid",`, `more invalid JSON`},
			wantErr:  `unmarshal`,
		},
		{
			name: "missing data",
			response: []string{
				// Valid JSON, but description is missing.
				`{"Summary":"summary"}`,
			},
			wantErr: `empty summary or description`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The input can be the same for each test because
			// the response is hard-coded.
			input := placeholderInput
			// Make sure Suggest calls defaultPrompt (or its equivalent).
			// A separate test checks that defaultPrompt is correct.
			c := &testCli{
				prompt:   mustGetDefaultPrompt(input),
				response: tt.response,
			}
			_, gotErr := Suggest(context.Background(), c, input)
			if gotErr == nil || !strings.Contains(gotErr.Error(), tt.wantErr) {
				t.Fatalf("Suggest() error = %v, want err containing %s", gotErr, tt.wantErr)
			}
		})
	}
}

func mustGetDefaultPrompt(in *Input) string {
	prompt, err := defaultPrompt(in)
	if err != nil {
		panic(err)
	}
	return prompt
}

type testCli struct {
	prompt   string
	response []string
}

func (c *testCli) GenerateText(_ context.Context, prompt string) ([]string, error) {
	if diff := cmp.Diff(c.prompt, prompt); diff != "" {
		return nil, fmt.Errorf("prompt mismatch (-want, +got):\n%s", diff)
	}
	return c.response, nil
}
