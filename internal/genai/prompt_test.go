// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genai

import "testing"

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
