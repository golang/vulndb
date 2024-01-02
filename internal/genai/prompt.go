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

var (
	//go:embed templates/preamble.txt
	defaultPreamble string

	//go:embed templates/prompt.tmpl
	promptTmpl string
	prompt     = template.Must(template.New("prompt").Funcs(template.FuncMap{"toJSON": toJSON}).Parse(promptTmpl))

	//go:embed data/examples.json
	defaultExamples []byte
)

const defaultMaxExamples = 15

func defaultPrompt(in *Input) (string, error) {
	var es Examples
	if err := es.ReadJSON(bytes.NewReader(defaultExamples)); err != nil {
		return "", err
	}
	return newPrompt(in, defaultPreamble, es, defaultMaxExamples)
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func newPrompt(in *Input, preamble string, examples Examples, maxExamples int) (string, error) {
	if len(examples) > maxExamples {
		examples = examples[:maxExamples]
	}
	var b strings.Builder
	if err := prompt.Execute(&b, struct {
		Preamble string
		Examples Examples
		Input    *Input
	}{
		Preamble: preamble,
		Examples: examples,
		Input:    in,
	}); err != nil {
		return "", err
	}
	return b.String(), nil
}
