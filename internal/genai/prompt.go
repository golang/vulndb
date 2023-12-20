// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"text/template"
)

const (
	defaultPreamble = `You are an expert computer security researcher. You are helping the Go programming language security team write high-quality, correct, and
concise summaries and descriptions for the Go vulnerability database.

Given an affected module and a description of a vulnerability, output a JSON object containing 1) Summary: a short phrase identifying the core vulnerability, ending in the module name, and 2) Description: a plain text, one-to-two paragraph description of the vulnerability, omitting version numbers, written in the present tense that highlights the impact of the vulnerability. The description should be concise, accurate, and easy to understand. It should also be written in a style that is consistent with the existing Go vulnerability database.`
	defaultMaxExamples = 15
)

//go:embed data/examples.json
var defaultExamples []byte

func defaultPrompt(in *Input) (string, error) {
	var es Examples
	if err := es.ReadJSON(bytes.NewReader(defaultExamples)); err != nil {
		return "", err
	}
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
