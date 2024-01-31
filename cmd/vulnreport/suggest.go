// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/genai"
	"golang.org/x/vulndb/internal/report"
)

var (
	interactive    = flag.Bool("i", false, "for suggest, interactive mode")
	numSuggestions = flag.Int("n", 1, "for suggest, the number of suggestions to generate (>1 can be slow)")
)

type suggest struct {
	ac *genai.GeminiClient

	filenameParser
}

func (suggest) name() string { return "suggest" }

func (suggest) usage() (string, string) {
	const desc = "(EXPERIMENTAL) use AI to suggest summary and description for YAML reports"
	return filenameArgs, desc
}

func (s *suggest) setup(ctx context.Context) error {
	ac, err := genai.NewGeminiClient(ctx)
	if err != nil {
		return err
	}
	s.ac = ac
	return nil
}

func (s *suggest) close() error {
	if s.ac == nil {
		return nil
	}
	return s.ac.Close()
}

func (s *suggest) run(ctx context.Context, filename string) (err error) {
	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	log.Info("contacting the Gemini API...")
	suggestions, err := suggestions(ctx, s.ac, r, *numSuggestions)
	if err != nil {
		return err
	}
	found := len(suggestions)

	log.Outf("== AI-generated suggestions for report %s ==\n", r.ID)

	for i, s := range suggestions {
		log.Outf("\nSuggestion %d/%d\nsummary: %s\ndescription: %s\n",
			i+1, found, s.Summary, s.Description)

		// In interactive mode, allow user to accept the suggestion,
		// see the next one, or quit.
		// TODO(tatianabradley): In interactive mode, call the API as requested
		// instead of upfront.
		if *interactive {
			if i == found-1 {
				log.Outf("\naccept or quit? (a=accept/Q=quit) ")
			} else {
				log.Outf("\naccept, see next suggestion, or quit? (a=accept/n=next/Q=quit) ")
			}

			var choice string
			if _, err := fmt.Scanln(&choice); err != nil {
				return err
			}
			switch choice {
			case "a":
				applySuggestion(r, s)
				if err := r.Write(filename); err != nil {
					log.Err(err)
				}
				return nil
			case "n":
				continue
			default:
				return nil
			}
		}
	}

	return nil
}

func suggestions(ctx context.Context, c genai.Client, r *report.Report, max int) (suggestions []*genai.Suggestion, err error) {
	attempts := 0
	maxAttempts := max + 2
	for len(suggestions) < max && attempts < maxAttempts {
		s, err := genai.Suggest(ctx, c, &genai.Input{
			Module:      r.Modules[0].Module,
			Description: r.Description.String(),
		})
		if err != nil {
			return nil, fmt.Errorf("GenAI API error: %s", err)
		}
		suggestions = append(suggestions, s...)
		attempts++
	}

	if len(suggestions) > max {
		suggestions = suggestions[:max]
	}

	found := len(suggestions)
	if found == 0 {
		return nil, fmt.Errorf("could not generate any valid suggestions for report %s after %d attempts", r.ID, attempts)
	}

	return suggestions, nil
}

func applySuggestion(r *report.Report, s *genai.Suggestion) {
	r.Summary = report.Summary(s.Summary)
	r.Description = report.Description(s.Description)
	r.Fix(nil)
}
