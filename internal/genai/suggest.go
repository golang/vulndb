// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
)

type Input struct {
	// The path of the affected module to include in the summary.
	Module string
	// The original description (can be copied from a GHSA or CVE)
	// of the vulnerability.
	Description string
}

type Suggestion struct {
	// A short summary of the vulnerability.
	Summary string
	// A re-written description of the vulnerability.
	Description string
}

type Client interface {
	GenerateText(context.Context, string) ([]string, error)
}

// Suggest uses generative AI to generate suggestions for vulnerability
// reports based on the input.
func Suggest(ctx context.Context, c Client, in *Input) ([]*Suggestion, error) {
	prompt, err := defaultPrompt(in)
	if err != nil {
		return nil, err
	}

	candidates, err := c.GenerateText(ctx, prompt)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, errors.New("GenAI API returned no candidates")
	}

	var suggestions []*Suggestion
	var candidateErr error
	for _, c := range candidates {
		s, err := parseSuggestion(c)
		// Skip invalid candidates, but store the error in case
		// we can't find anything valid.
		if err != nil {
			candidateErr = err
			continue
		}
		suggestions = append(suggestions, s)
	}

	if len(suggestions) == 0 && candidateErr != nil {
		return nil, fmt.Errorf("GenAI API returned no valid candidates: example error: %w", candidateErr)
	}

	return suggestions, nil
}

func parseSuggestion(str string) (*Suggestion, error) {
	var s Suggestion
	if err := json.Unmarshal([]byte(str), &s); err != nil {
		return nil, fmt.Errorf("invalid candidate %q: unmarshal: %w", str, err)
	}
	if s.Summary == "" || s.Description == "" {
		return nil, fmt.Errorf("invalid candidate %q: empty summary or description", str)
	}
	return &s, nil
}
