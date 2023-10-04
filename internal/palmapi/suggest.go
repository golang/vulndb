// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package palmapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"
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

// Suggest uses the PaLM API to generate suggestions for vulnerability
// reports based on the input.
// This function must be called from the root of the vulndb repo,
// as it accesses a specific file to read examples.
func (c *Client) Suggest(in *Input) ([]*Suggestion, error) {
	examples, err := readFile(filepath.Join("internal", "palmapi", dataFolder, jsonFile))
	if err != nil {
		return nil, err
	}
	prompt, err := defaultPrompt(in, examples)
	if err != nil {
		return nil, err
	}
	return c.suggest(prompt)
}

func (c *Client) suggest(prompt string) ([]*Suggestion, error) {
	response, err := c.GenerateText(prompt)
	if err != nil {
		return nil, err
	}
	if response == nil || len(response.Candidates) == 0 {
		return nil, errors.New("PaLM API returned no candidates")
	}
	var suggestions []*Suggestion
	var candidateErr error
	for _, c := range response.Candidates {
		var s Suggestion
		// Skip invalid candidates, but store the error in case
		// we can't find anything valid.
		if err := json.Unmarshal([]byte(c.Output), &s); err != nil {
			candidateErr = fmt.Errorf("invalid candidate %q: unmarshal: %w", c.Output, err)
			continue
		}
		if s.Summary == "" || s.Description == "" {
			candidateErr = fmt.Errorf("invalid candidate %q: empty summary or description", c.Output)
			continue
		}
		suggestions = append(suggestions, &s)
	}

	if len(suggestions) == 0 && candidateErr != nil {
		return nil, fmt.Errorf("PaLM API returned no valid candidates: example error: %w", candidateErr)
	}

	return suggestions, nil
}

const (
	defaultPreamble = `You are an expert computer security researcher. You are helping the Go programming language security team write high-quality, correct, and
concise summaries and descriptions for the Go vulnerability database.

Given an affected module and a description of a vulnerability, output a JSON object containing 1) Summary: a short phrase identifying the core vulnerability, ending in the module name, and 2) Description: a plain text, one-to-two paragraph description of the vulnerability, omitting version numbers, written in the present tense that highlights the impact of the vulnerability. The description should be concise, accurate, and easy to understand. It should also be written in a style that is consistent with the existing Go vulnerability database.`
	defaultMaxExamples = 15
)

func defaultPrompt(in *Input, es Examples) (string, error) {
	return newPrompt(in, defaultPreamble, es, defaultMaxExamples)
}

const (
	promptTmpl = `
{{ range .Examples }}
input: {{ .Input | toJSON }}
output: {{ .Suggestion | toJSON }}{{ end }}
input: {{ .Input | toJSON }}
output:`
)

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

var prompt = template.Must(template.New("prompt").Funcs(template.FuncMap{"toJSON": toJSON}).Parse(promptTmpl))

func newPrompt(in *Input, preamble string, examples Examples, maxExamples int) (string, error) {
	if len(examples) > maxExamples {
		examples = examples[:maxExamples]
	}
	var b strings.Builder
	if _, err := b.WriteString(preamble); err != nil {
		return "", err
	}
	if err := prompt.Execute(&b, struct {
		Examples Examples
		Input    *Input
	}{
		Examples: examples,
		Input:    in,
	}); err != nil {
		return "", err
	}
	return b.String(), nil
}
