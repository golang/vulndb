// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/palmapi"
	"golang.org/x/vulndb/internal/report"
)

var (
	interactive    = flag.Bool("i", false, "for suggest, interactive mode")
	numSuggestions = flag.Int("n", 4, "for suggest, the number of suggestions to attempt to generate (max is 8)")
)

func suggest(_ context.Context, filename string) (err error) {
	defer derrors.Wrap(&err, "suggest(%q)", filename)

	c := palmapi.NewDefaultClient()

	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	suggestions, err := c.Suggest(&palmapi.Input{
		Module:      r.Modules[0].Module,
		Description: r.Description.String(),
	})
	if err != nil {
		return fmt.Errorf("PaLM API error: %s", err)
	}
	if len(suggestions) > *numSuggestions {
		suggestions = suggestions[:*numSuggestions]
	}

	found := len(suggestions)
	if found == 0 {
		return fmt.Errorf("could not generate any valid suggestions for report %s (try again?)", r.ID)
	}

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
				r.Summary = report.Summary(s.Summary)
				r.Description = report.Description(s.Description)
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
