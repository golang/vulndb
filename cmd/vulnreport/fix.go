// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

var (
	force       = flag.Bool("f", false, "for fix, force Fix to run even if there are no lint errors")
	skipAlias   = flag.Bool("skip-alias", false, "for fix, skip adding new GHSAs and CVEs")
	skipSymbols = flag.Bool("skip-symbols", false, "for lint and fix, don't load package for symbols checks")
)

type fix struct {
	pc *proxy.Client
	gc *ghsa.Client

	filenameParser
}

func (fix) name() string { return "fix" }

func (fix) usage() (string, string) {
	const desc = "fix a YAML report"
	return filenameArgs, desc
}

func (f *fix) setup(ctx context.Context) error {
	f.pc = proxy.NewDefaultClient()
	f.gc = ghsa.NewClient(ctx, *githubToken)
	return nil
}

func (*fix) close() error { return nil }

func (f *fix) run(ctx context.Context, filename string) (err error) {
	r, err := report.Read(filename)
	if err != nil {
		return err
	}

	return fixReport(ctx, r, filename, f.pc, f.gc)
}

func fixReport(ctx context.Context, r *report.Report, filename string, pc *proxy.Client, gc *ghsa.Client) error {
	if err := r.CheckFilename(filename); err != nil {
		return err
	}

	// We may make partial progress on fixing a report, so write the
	// report even if a fatal error occurs somewhere.
	defer func() {
		if err := r.Write(filename); err != nil {
			log.Err(err)
		}
	}()

	if lints := r.Lint(pc); *force || len(lints) > 0 {
		r.Fix(pc)
	}
	if lints := r.Lint(pc); len(lints) > 0 {
		log.Warnf("%s still has lint errors after fix:\n\t- %s", filename, strings.Join(lints, "\n\t- "))
	}

	if !*skipSymbols {
		log.Infof("%s: checking packages and symbols (use -skip-symbols to skip this)", r.ID)
		if err := checkReportSymbols(r); err != nil {
			return err
		}
	}
	if !*skipAlias {
		log.Infof("%s: checking for missing GHSAs and CVEs (use -skip-alias to skip this)", r.ID)
		if added := addMissingAliases(ctx, r, gc); added > 0 {
			log.Infof("%s: added %d missing aliases", r.ID, added)
		}
	}

	if !r.IsExcluded() {
		if err := writeOSV(r); err != nil {
			return err
		}
	}

	if r.CVEMetadata != nil {
		if err := writeCVE(r); err != nil {
			return err
		}
	}

	return nil
}

func checkReportSymbols(r *report.Report) error {
	if r.IsExcluded() {
		log.Infof("%s is excluded, skipping symbol checks\n", r.ID)
		return nil
	}
	for _, m := range r.Modules {
		if m.IsFirstParty() {
			gover := runtime.Version()
			ver := semverForGoVersion(gover)
			// If some symbol is in the std library at a different version,
			// we may derive the wrong symbols for this package and other.
			// In this case, skip updating DerivedSymbols.
			affected, err := osvutils.AffectsSemver(report.AffectedRanges(m.Versions), ver)
			if err != nil {
				return err
			}
			if ver == "" || !affected {
				log.Warnf("%s: current Go version %q is not in a vulnerable range, skipping symbol checks for module %s\n", r.ID, gover, m.Module)
				continue
			}
			if ver != m.VulnerableAt {
				log.Warnf("%s: current Go version %q does not match vulnerable_at version (%s) for module %s\n", r.ID, ver, m.VulnerableAt, m.Module)
			}
		}

		for _, p := range m.Packages {
			if p.SkipFix != "" {
				log.Infof("%s: skipping symbol checks for package %s (reason: %q)\n", r.ID, p.Package, p.SkipFix)
				continue
			}
			syms, err := symbols.Exported(m, p)
			if err != nil {
				return fmt.Errorf("package %s: %w", p.Package, err)
			}
			// Remove any derived symbols that were marked as excluded by a human.
			syms = removeExcluded(syms, p.ExcludedSymbols)
			if !cmp.Equal(syms, p.DerivedSymbols) {
				p.DerivedSymbols = syms
				log.Infof("%s: updated derived symbols for package %s\n", r.ID, p.Package)
			}
		}
	}

	return nil
}

func removeExcluded(syms, excluded []string) []string {
	if len(excluded) == 0 {
		return syms
	}
	var newSyms []string
	for _, d := range syms {
		if slices.Contains(excluded, d) {
			log.Infof("removed excluded symbol %s\n", d)
			continue
		}
		newSyms = append(newSyms, d)
	}
	return newSyms
}

// Regexp for matching go tags. The groups are:
// 1  the major.minor version
// 2  the patch version, or empty if none
// 3  the entire prerelease, if present
// 4  the prerelease type ("beta" or "rc")
// 5  the prerelease number
var tagRegexp = regexp.MustCompile(`^go(\d+\.\d+)(\.\d+|)((beta|rc)(\d+))?$`)

// versionForTag returns the semantic version for a Go version string,
// or "" if the version string doesn't correspond to a Go release or beta.
func semverForGoVersion(v string) string {
	m := tagRegexp.FindStringSubmatch(v)
	if m == nil {
		return ""
	}
	version := m[1]
	if m[2] != "" {
		version += m[2]
	} else {
		version += ".0"
	}
	if m[3] != "" {
		version += "-" + m[4] + "." + m[5]
	}
	return version
}
