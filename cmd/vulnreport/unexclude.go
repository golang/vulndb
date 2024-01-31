// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"os"

	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/genai"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

type unexclude struct {
	gc *ghsa.Client
	pc *proxy.Client
	ac *genai.GeminiClient

	filenameParser
}

func (unexclude) name() string { return "unexclude" }

func (unexclude) usage() (string, string) {
	const desc = "converts excluded YAML reports to regular YAML reports"
	return filenameArgs, desc
}

func (u *unexclude) setup(ctx context.Context) error {
	u.gc = ghsa.NewClient(ctx, *githubToken)
	u.pc = proxy.NewDefaultClient()

	if *useAI {
		ac, err := genai.NewGeminiClient(ctx)
		if err != nil {
			return err
		}
		u.ac = ac
	}

	return nil
}

func (u *unexclude) close() error {
	if u.ac != nil {
		return u.ac.Close()
	}
	return nil
}

// unexclude converts an excluded report into a regular report.
func (u *unexclude) run(ctx context.Context, filename string) (err error) {
	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	if !r.IsExcluded() {
		log.Infof("report %s is not excluded, can't unexclude", r.ID)
		return nil
	}

	// Usually, we only unexclude reports that are effectively private or not importable.
	if r.Excluded != "EFFECTIVELY_PRIVATE" && r.Excluded != "NOT_IMPORTABLE" {
		if *force {
			log.Warnf("report %s is excluded for reason %q, but -f was specified, continuing", r.ID, r.Excluded)
		} else {
			log.Infof("report %s is excluded for reason %q - we don't unexclude these report types (use -f to force)", r.ID, r.Excluded)
			return nil
		}
	}

	log.Infof("creating regular report based on excluded report %s", filename)
	aliases := r.Aliases()
	id := r.ID
	var modulePath string
	if len(r.Modules) > 0 {
		modulePath = r.Modules[0].Module
	}
	newR, err := reportFromAliases(ctx, id, modulePath, aliases, u.pc, u.gc, u.ac)
	if err != nil {
		return err
	}

	// Remove description because this is a "basic" report.
	newR.Description = ""

	if err := os.Remove(filename); err != nil {
		log.Errf("could not remove excluded report: %v", err)
	}
	log.Infof("removed excluded report %s", filename)

	newFilename, err := writeReport(newR)
	if err != nil {
		return err
	}
	log.Out(newFilename)

	return nil
}
