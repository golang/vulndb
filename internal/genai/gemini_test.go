// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import (
	"context"
	"testing"

	gemini "github.com/google/generative-ai-go/genai"
	"github.com/google/go-cmp/cmp"
)

func TestGemini(t *testing.T) {
	c := testGeminiClient()

	got, err := c.GenerateText(context.Background(), "say hello")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Hello there! How can I assist you today?"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GenerateText mismatch (-want, +got):\n%s", diff)
	}
}

func testGeminiClient() *GeminiClient {
	return &GeminiClient{
		model:  testModel{},
		closer: testCloser{},
	}
}

type testModel struct{}

func (_ testModel) GenerateContent(ctx context.Context, parts ...gemini.Part) (*gemini.GenerateContentResponse, error) {
	// TODO(tatianabradley): Improve testing by replaying a real API response.
	return &gemini.GenerateContentResponse{
		Candidates: []*gemini.Candidate{{
			Content: &gemini.Content{
				Parts: []gemini.Part{
					gemini.Text("Hello there! How can I assist you today?"),
				},
			},
		}},
	}, nil
}

type testCloser struct{}

func (_ testCloser) Close() error { return nil }
