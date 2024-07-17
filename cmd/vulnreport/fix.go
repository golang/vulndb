// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/slices"
	"golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/pkgsite"
	"golang.org/x/vulndb/internal/report"
	"golang.org/x/vulndb/internal/symbols"
)

var (
	force        = flag.Bool("f", false, "for fix, force Fix to run even if there are no lint errors")
	skipChecks   = flag.Bool("skip-checks", false, "for fix, skip all checks except lint")
	skipAlias    = flag.Bool("skip-alias", false, "for fix, skip adding new GHSAs and CVEs")
	skipSymbols  = flag.Bool("skip-symbols", false, "for fix, don't load package for symbols checks")
	skipPackages = flag.Bool("skip-packages", false, "for fix, don't check if packages exist")
	skipRefs     = flag.Bool("skip-refs", false, "for fix, don't check if references exist")
)

type fix struct {
	*fixer
	*filenameParser
	noSkip
}

func (fix) name() string { return "fix" }

func (fix) usage() (string, string) {
	const desc = "fix a YAML report"
	return filenameArgs, desc
}

func (f *fix) setup(ctx context.Context, env environment) error {
	f.fixer = new(fixer)
	f.filenameParser = new(filenameParser)
	return setupAll(ctx, env, f.fixer, f.filenameParser)
}

func (*fix) close() error { return nil }

func (f *fix) run(ctx context.Context, input any) error {
	r := input.(*yamlReport)
	return f.fixAndWriteAll(ctx, r, false)
}

type fixer struct {
	*linter
	*aliasFinder
	*fileWriter

	pkc *pkgsite.Client
}

func (f *fixer) setup(ctx context.Context, env environment) error {
	f.pkc = env.PkgsiteClient()
	f.linter = new(linter)
	f.aliasFinder = new(aliasFinder)
	f.fileWriter = new(fileWriter)
	return setupAll(ctx, env, f.linter, f.aliasFinder, f.fileWriter)
}

func (f *fixer) fixAndWriteAll(ctx context.Context, r *yamlReport, addNotes bool) error {
	fixed := f.fix(ctx, r, addNotes)

	// fix may have partially succeeded, so write the report no matter what.
	if err := f.write(r); err != nil {
		return err
	}

	if fixed {
		return f.writeDerived(r)
	}

	return fmt.Errorf("%s: could not fix all errors; requires manual review", r.ID)
}

func (f *fixer) fix(ctx context.Context, r *yamlReport, addNotes bool) (fixed bool) {
	fixed = true

	if lints := r.Lint(f.pxc); *force || len(lints) > 0 {
		r.Fix(f.pxc)
	}

	if !*skipChecks {
		if ok := f.allChecks(ctx, r, addNotes); !ok {
			fixed = false
		}
	}

	// Check for remaining lint errors.
	if addNotes {
		if r.LintAsNotes(f.pxc) {
			log.Warnf("%s: still has lint errors after fix", r.ID)
			fixed = false
		}
	} else {
		if lints := r.Lint(f.pxc); len(lints) > 0 {
			log.Warnf("%s: still has lint errors after fix:\n\t- %s", r.ID, strings.Join(lints, "\n\t- "))
			fixed = false
		}
	}

	return fixed
}

// allChecks runs additional checks/fixes that are slow and require a network connection.
// Unlike lint checks which cannot be bypassed, these *should* pass before submit,
// but it is possible to bypass them if needed with the "-skip-checks" flag.
func (f *fixer) allChecks(ctx context.Context, r *yamlReport, addNotes bool) (ok bool) {
	ok = true
	fixErr := func(f string, v ...any) {
		log.Errf(r.ID+": "+f, v...)
		if addNotes {
			r.AddNote(report.NoteTypeFix, f, v...)
		}
		ok = false
	}

	if !*skipPackages {
		log.Infof("%s: checking that all packages exist", r.ID)
		if err := r.CheckPackages(ctx, f.pkc); err != nil {
			fixErr("package error: %s", err)
		}
	}

	if !*skipSymbols {
		log.Infof("%s: checking symbols (use -skip-symbols to skip this)", r.ID)
		if err := r.checkSymbols(); err != nil {
			fixErr("symbol error: %s", err)
		}
	}

	if !*skipAlias {
		log.Infof("%s: checking for missing GHSAs and CVEs (use -skip-alias to skip this)", r.ID)
		if added := r.addMissingAliases(ctx, f.aliasFinder); added > 0 {
			log.Infof("%s: added %d missing aliases", r.ID, added)
		}
	}

	if !*skipRefs {
		// For now, this is a fix check instead of a lint.
		log.Infof("%s: checking that all references are reachable", r.ID)
		checkRefs(r.References, fixErr)
	}

	return ok
}

func checkRefs(refs []*report.Reference, fixErr func(f string, v ...any)) {
	for _, r := range refs {
		resp, err := http.Head(r.URL)
		if err != nil {
			fixErr("%q may not exist: %v", r.URL, err)
			continue
		}
		defer resp.Body.Close()

		// For now, only error on status 404, which is unambiguously a problem.
		// An experiment to error on all non-200 status codes brought up some
		// ambiguous cases where the link is still viewable in a browser, e.g.:
		// - 429 Too Many Requests (https://vuldb.com/)
		// - 503 Service Unavailable (http://blog.recurity-labs.com/2017-08-10/scm-vulns):
		// - 403 Forbidden (https://www.sap.com/documents/2022/02/fa865ea4-167e-0010-bca6-c68f7e60039b.html)
		if resp.StatusCode == http.StatusNotFound {
			fixErr("%q may not exist: HTTP GET returned status %s", r.URL, resp.Status)
		}
	}
}

func (r *yamlReport) checkSymbols() error {
	if r.IsExcluded() {
		log.Infof("%s: excluded, skipping symbol checks", r.ID)
		return nil
	}
	if len(r.Modules) == 0 {
		log.Infof("%s: no modules, skipping symbol checks", r.ID)
		return nil
	}
	for _, m := range r.Modules {
		if len(m.Packages) == 0 {
			log.Infof("%s: module %s has no packages, skipping symbol checks", r.ID, m.Module)
			return nil
		}

		if m.IsFirstParty() {
			gover := runtime.Version()
			ver := semverForGoVersion(gover)
			// If some symbol is in the std library at a different version,
			// we may derive the wrong symbols for this package and other.
			// In this case, skip updating DerivedSymbols.
			ranges, err := m.Versions.ToSemverRanges()
			if err != nil {
				return err
			}
			affected, err := osvutils.AffectsSemver(ranges, ver)
			if err != nil {
				return err
			}
			if ver == "" || !affected {
				log.Warnf("%s: current Go version %q is not in a vulnerable range, skipping symbol checks for module %s", r.ID, gover, m.Module)
				continue
			}
			if m.VulnerableAt == nil || ver != m.VulnerableAt.Version {
				log.Warnf("%s: current Go version %q does not match vulnerable_at version (%s) for module %s", r.ID, ver, m.VulnerableAt, m.Module)
			}
		}

		for _, p := range m.Packages {
			if len(p.AllSymbols()) == 0 && p.SkipFixSymbols != "" {
				log.Warnf("%s: skip_fix not needed", r.Filename)
				continue
			}
			if len(p.AllSymbols()) == 0 {
				log.Infof("%s: skipping symbol checks for package %s (no symbols)", r.ID, p.Package)
				continue
			}
			if p.SkipFixSymbols != "" {
				log.Infof("%s: skipping symbol checks for package %s (reason: %q)", r.ID, p.Package, p.SkipFixSymbols)
				continue
			}
			syms, err := symbols.Exported(m, p)
			if err != nil {
				return fmt.Errorf("package %s: %w", p.Package, err)
			}
			// Remove any derived symbols that were marked as excluded by a human.
			syms = removeExcluded(r.ID, syms, p.ExcludedSymbols)
			if !cmp.Equal(syms, p.DerivedSymbols) {
				p.DerivedSymbols = syms
				log.Infof("%s: updated derived symbols for package %s", r.ID, p.Package)
			}
		}
	}

	return nil
}

func removeExcluded(id string, syms, excluded []string) []string {
	if len(excluded) == 0 {
		return syms
	}
	var newSyms []string
	for _, d := range syms {
		if slices.Contains(excluded, d) {
			log.Infof("%s: removed excluded symbol %s", id, d)
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
