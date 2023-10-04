// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package palmapi

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-cmp/cmp"
)

// Examples represents a list of input/output pairs to be used
// as examples to follow by the Suggest function.
// Can be used to create few-shot prompts or fine-tune a model.
type Examples []*Example

type Example struct {
	Input      `json:"Input"`
	Suggestion `json:"Suggestion"`
}

const (
	dataFolder = "data"
	promptFile = "prompt.txt"
	csvFile    = "examples.csv"
	jsonFile   = "examples.json"
)

// WriteFiles writes the examples to the given folder in the following formats:
//   - <folder>/data/examples.json: a JSON array of the examples
//     (used directly by the Suggest function)
//   - <folder>/data/examples.csv: a CSV-formatted list of each example,
//     where the input and output are comma-separated JSON objects.
//     Can be used as an input to a Makersuite data prompt.
//   - <folder>/data/prompt.txt: the prompt that will be used by Suggest
//     (with placeholder data for the final input)
func (es Examples) WriteFiles(folder string) error {
	dir := filepath.Join(folder, dataFolder)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}

	for filename, write := range map[string]func(w io.Writer) error{
		promptFile: es.writePrompt,
		csvFile:    es.writeCSV,
		jsonFile:   es.writeJSON,
	} {
		f, err := os.Create(filepath.Join(folder, dataFolder, filename))
		if err != nil {
			return err
		}
		defer f.Close()
		if err := write(f); err != nil {
			return err
		}
	}
	return nil
}

func checkFiles(folder string, minExamples int) error {
	fpath := func(fname string) string {
		return filepath.Join(folder, dataFolder, fname)
	}

	// Check the JSON file.
	jsonExamples, err := readFile(fpath(jsonFile))
	if err != nil {
		return err
	}
	if len(jsonExamples) < minExamples {
		return fmt.Errorf("%s has fewer than %d examples", jsonFile, minExamples)
	}

	// Check the CSV file.
	csvExamples, err := readFile(fpath(csvFile))
	if err != nil {
		return err
	}
	if diff := cmp.Diff(csvExamples, jsonExamples); diff != "" {
		return fmt.Errorf("CSV and JSON examples don't match (-csv +json):\n%s", diff)
	}

	// Check the example prompt.
	b, err := os.ReadFile(fpath(promptFile))
	if err != nil {
		return fmt.Errorf("could not read %s: %v", promptFile, err)
	}
	gotPrompt := string(b)
	if !strings.HasPrefix(gotPrompt, defaultPreamble) {
		return fmt.Errorf("prompt in %s does not start with default preamble", promptFile)
	}
	wantPrompt, err := jsonExamples.placeholderPrompt()
	if err != nil {
		return err
	}
	if diff := cmp.Diff(wantPrompt, gotPrompt); diff != "" {
		return fmt.Errorf("prompt mismatch (-want +got):\n%s", diff)
	}

	return nil
}

func (es *Examples) ReadJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	return d.Decode(es)
}

func readFile(filename string) (Examples, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var examples Examples
	switch filepath.Ext(filename) {
	case ".csv":
		if err := examples.readCSV(file); err != nil {
			return nil, err
		}
	case ".json":
		if err := examples.ReadJSON(file); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported file type: %s", filename)
	}
	return examples, nil
}

func (es Examples) placeholderPrompt() (string, error) {
	return defaultPrompt(&Input{
		Module:      "INPUT MODULE",
		Description: "INPUT DESCRIPTION",
	}, es)
}

func (es Examples) writePrompt(w io.Writer) error {
	prompt, err := es.placeholderPrompt()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(prompt))
	return err
}

func (es Examples) writeCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	for _, e := range es {
		in, out, err := e.marshal()
		if err != nil {
			return err
		}
		if err := cw.Write([]string{in, out}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func (es *Examples) readCSV(r io.Reader) error {
	cr := csv.NewReader(r)
	records, err := cr.ReadAll()
	if err != nil {
		return err
	}
	for _, record := range records {
		if len(record) != 2 {
			return fmt.Errorf("unexpected CSV record: %v", record)
		}
		e, err := unmarshal(record[0], record[1])
		if err != nil {
			return err
		}
		*es = append(*es, e)
	}
	return nil
}

func (es Examples) writeJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(es)
}

func unmarshal(input string, output string) (*Example, error) {
	var e Example
	if err := json.Unmarshal([]byte(input), &e.Input); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(output), &e.Suggestion); err != nil {
		return nil, err
	}
	return &e, nil
}

func (e *Example) marshal() (input string, output string, err error) {
	ib, err := json.Marshal(e.Input)
	if err != nil {
		return "", "", err
	}
	ob, err := json.Marshal(e.Suggestion)
	if err != nil {
		return "", "", err
	}
	return string(ib), string(ob), nil
}
