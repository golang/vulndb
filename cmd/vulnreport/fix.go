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
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

var (
	force       = flag.Bool("f", false, "for fix, force Fix to run even if there are no lint errors")
	skipAlias   = flag.Bool("skip-alias", false, "for fix, skip adding new GHSAs and CVEs")
	skipSymbols = flag.Bool("skip-symbols", false, "for lint and fix, don't load package for symbols checks")
)

type fix struct {
	*fixer
	filenameParser
}

func (fix) name() string { return "fix" }

func (fix) usage() (string, string) {
	const desc = "fix a YAML report"
	return filenameArgs, desc
}

func (f *fix) setup(ctx context.Context) error {
	f.fixer = new(fixer)
	return setupAll(ctx, f.fixer)
}

func (*fix) close() error { return nil }

func (f *fix) run(ctx context.Context, filename string) (err error) {
	r, err := report.ReadStrict(filename)
	if err != nil {
		return err
	}
	return f.fixAndWriteAll(ctx, r)
}

type fixer struct {
	*linter
	*aliasFinder
}

func (f *fixer) setup(ctx context.Context) error {
	f.linter = new(linter)
	f.aliasFinder = new(aliasFinder)
	return setupAll(ctx, f.linter, f.aliasFinder)
}

func (f *fixer) fixAndWriteAll(ctx context.Context, r *report.Report) error {
	fixed := f.fix(ctx, r, false)

	// fix may have partially succeeded, so write the report no matter what.
	if err := writeReport(r); err != nil {
		return err
	}

	if fixed {
		return writeDerived(r)
	}

	return fmt.Errorf("%s: could not fix all errors; requires manual review", r.ID)
}

func (f *fixer) fix(ctx context.Context, r *report.Report, addNotes bool) (fixed bool) {
	fixed = true

	if lints := r.Lint(f.pc); *force || len(lints) > 0 {
		r.Fix(f.pc)
	}

	if !*skipSymbols {
		log.Infof("%s: checking packages and symbols (use -skip-symbols to skip this)", r.ID)
		if err := checkReportSymbols(r); err != nil {
			log.Errf("%s: package or symbol error: %s", r.ID, err)
			if addNotes {
				r.AddNote(report.NoteTypeFix, "package or symbol error: %s", err)
			}
			fixed = false
		}
	}

	if !*skipAlias {
		log.Infof("%s: checking for missing GHSAs and CVEs (use -skip-alias to skip this)", r.ID)
		if added := f.addMissingAliases(ctx, r); added > 0 {
			log.Infof("%s: added %d missing aliases", r.ID, added)
		}
	}

	// TODO(tatianabradley): this should be a lint check instead.
	if hasUnaddressedTodos(r) {
		log.Warnf("%s has unaddressed %q fields", r.ID, "TODO:")
		if addNotes {
			r.AddNote(report.NoteTypeFix, "%s has unaddressed %q fields", r.ID, "TODO:")
		}
		fixed = false
	}

	// Check for remaining lint errors.
	if addNotes {
		if r.LintAsNotes(f.pc) {
			log.Warnf("%s still has lint errors after fix", r.ID)
			fixed = false
		}
	} else {
		if lints := r.Lint(f.pc); len(lints) > 0 {
			log.Warnf("%s still has lint errors after fix:\n\t- %s", r.ID, strings.Join(lints, "\n\t- "))
			fixed = false
		}
	}

	return fixed
}

// hasUnaddressedTodos returns true if report has any unaddressed todos in the
// report, i.e. starts with "TODO:".
func hasUnaddressedTodos(r *report.Report) bool {
	is := func(s string) bool { return strings.HasPrefix(s, "TODO:") }
	any := func(ss []string) bool { return slices.IndexFunc(ss, is) >= 0 }

	if is(string(r.Excluded)) {
		return true
	}
	for _, m := range r.Modules {
		if is(m.Module) {
			return true
		}
		for _, v := range m.Versions {
			if is(string(v.Introduced)) {
				return true
			}
			if is(string(v.Fixed)) {
				return true
			}
		}
		if is(string(m.VulnerableAt)) {
			return true
		}
		for _, p := range m.Packages {
			if is(p.Package) || is(p.SkipFix) || any(p.Symbols) || any(p.DerivedSymbols) {
				return true
			}
		}
	}
	for _, ref := range r.References {
		if is(ref.URL) {
			return true
		}
	}
	if any(r.CVEs) || any(r.GHSAs) {
		return true
	}
	return is(r.Summary.String()) || is(r.Description.String()) || any(r.Credits)
}

func checkReportSymbols(r *report.Report) error {
	if r.IsExcluded() {
		log.Infof("%s is excluded, skipping symbol checks", r.ID)
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
				log.Warnf("%s: current Go version %q is not in a vulnerable range, skipping symbol checks for module %s", r.ID, gover, m.Module)
				continue
			}
			if ver != m.VulnerableAt {
				log.Warnf("%s: current Go version %q does not match vulnerable_at version (%s) for module %s", r.ID, ver, m.VulnerableAt, m.Module)
			}
		}

		for _, p := range m.Packages {
			if p.SkipFix != "" {
				log.Infof("%s: skipping symbol checks for package %s (reason: %q)", r.ID, p.Package, p.SkipFix)
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
				log.Infof("%s: updated derived symbols for package %s", r.ID, p.Package)
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
			log.Infof("removed excluded symbol %s", d)
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
