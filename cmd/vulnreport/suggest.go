// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/genai"
	"golang.org/x/vulndb/internal/report"
)

var (
	interactive    = flag.Bool("i", false, "for suggest, interactive mode")
	numSuggestions = flag.Int("n", 4, "for suggest, the number of suggestions to attempt to generate (max is 8)")
	palm           = flag.Bool("palm", false, "use the legacy PaLM API instead of the Gemini API")
)

func suggestCmd(ctx context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "suggest(%q)", filename)

	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	var c genai.Client
	if *palm {
		infolog.Print("contacting the PaLM API...")
		c = genai.NewDefaultPaLMClient()
	} else {
		infolog.Print("contacting the Gemini API... (set flag -palm to use legacy PaLM API instead)")
		c, err = genai.NewGeminiClient(ctx)
		if err != nil {
			return err
		}
	}

	suggestions, err := suggest(ctx, c, r, *numSuggestions)
	if err != nil {
		return err
	}
	found := len(suggestions)

	outlog.Printf("== AI-generated suggestions for report %s ==\n", r.ID)

	for i, s := range suggestions {
		outlog.Printf("\nSuggestion %d/%d\nsummary: %s\ndescription: %s\n",
			i+1, found, s.Summary, s.Description)

		// In interactive mode, allow user to accept the suggestion,
		// see the next one, or quit.
		if *interactive {
			if i == found-1 {
				outlog.Printf("\naccept or quit? (a=accept/Q=quit) ")
			} else {
				outlog.Printf("\naccept, see next suggestion, or quit? (a=accept/n=next/Q=quit) ")
			}

			var choice string
			if _, err := fmt.Scanln(&choice); err != nil {
				return err
			}
			switch choice {
			case "a":
				applySuggestion(r, s)
				if err := r.Write(filename); err != nil {
					errlog.Println(err)
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

func suggest(ctx context.Context, c genai.Client, r *report.Report, max int) (suggestions []*genai.Suggestion, err error) {
	suggestions, err = genai.Suggest(ctx, c, &genai.Input{
		Module:      r.Modules[0].Module,
		Description: r.Description.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("GenAI API error: %s", err)
	}
	if len(suggestions) > max {
		suggestions = suggestions[:max]
	}

	found := len(suggestions)
	if found == 0 {
		return nil, fmt.Errorf("could not generate any valid suggestions for report %s (try again?)", r.ID)
	}

	return suggestions, nil
}

func applySuggestion(r *report.Report, s *genai.Suggestion) {
	r.Summary = report.Summary(s.Summary)
	r.Description = report.Description(s.Description)
	r.Fix(nil)
}
