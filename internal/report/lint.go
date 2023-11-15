// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/exp/slices"
	"golang.org/x/mod/module"
	"golang.org/x/vulndb/internal/cveschema5"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/ghsa"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/stdlib"
)

func (m *Module) checkModVersions(pc *proxy.Client) error {
	var notFound []string
	var nonCanonical []string
	for _, vr := range m.Versions {
		for _, v := range []string{vr.Introduced, vr.Fixed} {
			if v == "" {
				continue
			}
			c, err := pc.CanonicalModulePath(m.Module, v)
			if err != nil {
				notFound = append(notFound, v)
				continue
			}
			if c != m.Module {
				nonCanonical = append(nonCanonical, fmt.Sprintf("%s (canonical:%s)", v, c))
			}
		}
	}
	var sb strings.Builder
	nf, nc := len(notFound), len(nonCanonical)
	if nf > 0 {
		if nf == 1 {
			sb.WriteString(fmt.Sprintf("version %s does not exist", notFound[0]))
		} else {
			sb.WriteString(fmt.Sprintf("%d versions do not exist: %s", nf, strings.Join(notFound, ", ")))
		}
	}
	if nc > 0 {
		if nf > 0 {
			sb.WriteString(" and ")
		}
		sb.WriteString(fmt.Sprintf("module is not canonical at %d version(s):\n%s", nc, strings.Join(nonCanonical, "\n")))
	}
	if s := sb.String(); s != "" {
		return errors.New(s)
	}
	return nil
}

func (m *Module) lintStdLib(l *linter) {
	if len(m.Packages) == 0 {
		l.Error("missing package")
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			l.Error("missing package")
		}
	}
}

func (m *Module) lintThirdParty(l *linter) {
	if m.Module == "" {
		l.Error("missing module")
		return
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			l.Error("missing package")
			continue
		}
		if !strings.HasPrefix(p.Package, m.Module) {
			l.Error("module must be a prefix of package")
		}
		if err := module.CheckImportPath(p.Package); err != nil {
			l.Error(err)
		}
	}
}

func (m *Module) lintVersions(l *linter) {
	if u := len(m.UnsupportedVersions); u > 0 {
		l.Errorf("version issue: %d unsupported version(s)", u)
	}
	ranges := AffectedRanges(m.Versions)
	if v := m.VulnerableAt; v != "" {
		affected, err := osvutils.AffectsSemver(ranges, v)
		if err != nil {
			l.Errorf("version issue: %s", err)
		} else if !affected {
			l.Errorf("vulnerable_at version %s is not inside vulnerable range", v)
		}
	} else {
		if err := osvutils.ValidateRanges(ranges); err != nil {
			l.Errorf("version issue: %s", err)
		}
	}
}

func (r *Report) lintCVEs(l *linter) {
	for _, cve := range r.CVEs {
		if !cveschema5.IsCVE(cve) {
			l.Error("malformed cve identifier")
		}
	}
}

func (r *Report) lintGHSAs(l *linter) {
	for _, g := range r.GHSAs {
		if !ghsa.IsGHSA(g) {
			l.Errorf("%s is not a valid GHSA", g)
		}
	}
}

func (r *Report) lintRelated(l *linter) {
	if len(r.Related) == 0 {
		return
	}

	aliases := r.Aliases()
	for _, related := range r.Related {
		// In most cases, the related list is very short, so there's no
		// need create a map of aliases.
		if slices.Contains(aliases, related) {
			l.Errorf("related: identifier %s is also listed among aliases", related)
		}
		if !isIdentifier(related) {
			l.Errorf("related: %s is not a recognized identifier (CVE, GHSA or Go ID)", related)
		}
	}
}

func isIdentifier(id string) bool {
	return cveschema5.IsCVE(id) || ghsa.IsGHSA(id) || IsGoID(id)
}

var goIDregexp = regexp.MustCompile(`^GO-\d{4}-\d{4,}$`)

func IsGoID(s string) bool {
	return goIDregexp.MatchString(s)
}

const maxLineLength = 80

func (r *Report) lintLineLength(l *linter, field, content string) {
	for _, line := range strings.Split(content, "\n") {
		if len(line) <= maxLineLength {
			continue
		}
		if !strings.Contains(line, " ") {
			continue // A single long word is OK.
		}
		l.Errorf("%v contains line > %v characters long: %q", field, maxLineLength, line)
		return
	}
}

// Regex patterns for standard links.
var (
	prRegex       = regexp.MustCompile(`https://go.dev/cl/\d+`)
	commitRegex   = regexp.MustCompile(`https://go.googlesource.com/[^/]+/\+/([^/]+)`)
	issueRegex    = regexp.MustCompile(`https://go.dev/issue/\d+`)
	announceRegex = regexp.MustCompile(`https://groups.google.com/g/golang-(announce|dev|nuts)/c/([^/]+)`)

	nistRegex     = regexp.MustCompile(`^https://nvd.nist.gov/vuln/detail/(` + cveschema5.RegexStr + `)$`)
	ghsaLinkRegex = regexp.MustCompile(`^https://github.com/.*/(` + ghsa.Regex + `)$`)
	mitreRegex    = regexp.MustCompile(`^https://cve.mitre.org/.*(` + cveschema5.RegexStr + `)$`)
)

// Checks that the "links" section of a Report for a package in the
// standard library contains all necessary links, and no third-party links.
func (r *Report) lintStdLibLinks(l *linter) {
	var (
		hasFixLink      = false
		hasReportLink   = false
		hasAnnounceLink = false
	)
	for _, ref := range r.References {
		switch ref.Type {
		case osv.ReferenceTypeAdvisory:
			l.Errorf("%q: advisory reference should not be set for first-party issues", ref.URL)
		case osv.ReferenceTypeFix:
			hasFixLink = true
			if !prRegex.MatchString(ref.URL) && !commitRegex.MatchString(ref.URL) {
				l.Errorf("%q: fix reference should match %q or %q", ref.URL, prRegex, commitRegex)
			}
		case osv.ReferenceTypeReport:
			hasReportLink = true
			if !issueRegex.MatchString(ref.URL) {
				l.Errorf("%q: report reference should match %q", ref.URL, issueRegex)
			}
		case osv.ReferenceTypeWeb:
			if !announceRegex.MatchString(ref.URL) {
				l.Errorf("%q: web references should only contain announcement links matching %q", ref.URL, announceRegex)
			} else {
				hasAnnounceLink = true
			}
		}
	}
	if !hasFixLink {
		l.Error("references should contain at least one fix")
	}
	if !hasReportLink {
		l.Error("references should contain at least one report")
	}
	if !hasAnnounceLink {
		l.Errorf("references should contain an announcement link matching %q", announceRegex)
	}
}

func (r *Report) lintReferences(l *linter) {
	advisoryCount := 0
	for _, ref := range r.References {
		if !slices.Contains(osv.ReferenceTypes, ref.Type) {
			l.Errorf("%q is not a valid reference type", ref.Type)
		}
		u := ref.URL
		if _, err := url.ParseRequestURI(u); err != nil {
			l.Errorf("%q is not a valid URL", u)
		}
		if fixed := fixURL(u); fixed != u {
			l.Errorf("unfixed url: %q should be %q", u, fixURL(u))
		}
		if ref.Type == osv.ReferenceTypeAdvisory {
			advisoryCount++
		}
		if ref.Type != osv.ReferenceTypeAdvisory {
			// An ADVISORY reference to a CVE/GHSA indicates that it
			// is the canonical source of information on this vuln.
			//
			// A reference to a CVE/GHSA that is not an alias of this
			// report indicates that it may contain related information.
			//
			// A reference to a CVE/GHSA that appears in the CVEs/GHSAs
			// aliases is redundant.
			for _, re := range []*regexp.Regexp{nistRegex, mitreRegex, ghsaLinkRegex} {
				if m := re.FindStringSubmatch(ref.URL); len(m) > 0 {
					id := m[1]
					if slices.Contains(r.CVEs, id) || slices.Contains(r.GHSAs, id) {
						l.Errorf("redundant non-advisory reference to %v", id)
					}
				}
			}
		}
	}
	if advisoryCount > 1 {
		l.Error("references should contain at most one advisory link")
	}
	if r.IsFirstParty() && !r.IsExcluded() {
		r.lintStdLibLinks(l)
	}
}

func (d *Description) lint(l *linter, r *Report) {
	desc := d.String()

	r.lintLineLength(l, "description", desc)
	hasAdvisory := func() bool {
		for _, ref := range r.References {
			if ref.Type == osv.ReferenceTypeAdvisory {
				return true
			}
		}
		return false
	}
	if !r.IsExcluded() && desc == "" {
		if r.CVEMetadata != nil {
			l.Error("missing description (reports with Go CVEs must have a description)")
		} else if !hasAdvisory() {
			l.Error("missing advisory (reports without descriptions must have an advisory link)")
		}
	}
}

func (s *Summary) lint(l *linter, r *Report) {
	summary := s.String()
	if !r.IsExcluded() && len(summary) == 0 {
		l.Error("missing summary")
	}
	// Nothing to lint.
	if len(summary) == 0 {
		return
	}
	if strings.HasPrefix(summary, "TODO") {
		l.Error("summary contains a TODO")
	}
	if ln := len(summary); ln > 100 {
		l.Errorf("summary is too long: %d characters (max 100)", ln)
	}
	if strings.HasSuffix(summary, ".") {
		l.Error("summary should not end in a period (should be a phrase, not a sentence)")
	}
	for i, r := range summary {
		if i != 0 {
			break
		}
		if !unicode.IsUpper(r) {
			l.Error("summary should begin with a capital letter")
		}
	}
}

func (r *Report) IsExcluded() bool {
	return r.Excluded != ""
}

var (
	errWrongDir = errors.New("report is in incorrect directory")
	errWrongID  = errors.New("report ID mismatch")
)

// CheckFilename errors if the filename is inconsistent with the report.
func (r *Report) CheckFilename(filename string) (err error) {
	defer derrors.Wrap(&err, "CheckFilename(%q)", filename)

	dir := filepath.Base(filepath.Dir(filename)) // innermost folder
	excluded := r.IsExcluded()

	if excluded && dir != "excluded" {
		return fmt.Errorf("%w (want %s, found %s)", errWrongDir, "excluded", dir)
	}

	if !excluded && dir != "reports" {
		return fmt.Errorf("%w (want %s, found %s)", errWrongDir, "reports", dir)
	}

	wantID := GoID(filename)
	if r.ID != wantID {
		return fmt.Errorf("%w (want %s, found %s)", errWrongID, wantID, r.ID)
	}

	return nil
}

// Lint checks the content of a Report and outputs a list of strings
// representing lint errors.
// TODO: It might make sense to include warnings or informational things
// alongside errors, especially during for use during the triage process.
func (r *Report) Lint(pc *proxy.Client) []string {
	result := r.lint(pc)
	if pc == nil {
		result = append(result, "proxy client is nil; cannot perform all lint checks")
	}
	return result
}

// LintAsNotes works like Lint, but modifies r by adding any lints found
// to the notes section, instead of returning them.
// Removes any pre-existing lint notes.
// Returns true if any lints were found.
func (r *Report) LintAsNotes(pc *proxy.Client) bool {
	r.Notes = slices.DeleteFunc(r.Notes, func(n *Note) bool {
		return n.Type == NoteTypeLint
	})

	if lints := r.Lint(pc); len(lints) > 0 {
		slices.Sort(lints)
		for _, lint := range lints {
			r.Notes = append(r.Notes, &Note{
				Body: lint,
				Type: NoteTypeLint,
			})
		}
		return true
	}

	return false
}

// LintOffline performs all lint checks that don't require a network connection.
func (r *Report) LintOffline() []string {
	return r.lint(nil)
}

func (r *Report) lint(pc *proxy.Client) []string {
	l := NewLinter("")

	if r.ID == "" {
		l.Error("missing ID")
	}
	r.Summary.lint(l, r)
	r.Description.lint(l, r)
	r.Excluded.lint(l)

	r.lintModules(l, pc)

	r.CVEMetadata.lint(l, r)

	if r.IsExcluded() && len(r.Aliases()) == 0 {
		l.Error("excluded report must have at least one associated CVE or GHSA")
	}

	r.lintCVEs(l)
	r.lintGHSAs(l)
	r.lintRelated(l)

	r.lintReferences(l)

	return l.Errors()
}

func (m *Module) lint(l *linter, r *Report, pc *proxy.Client) {
	if m.IsFirstParty() {
		m.lintStdLib(l)
	} else {
		m.lintThirdParty(l)
		if pc != nil {
			if err := m.checkModVersions(pc); err != nil {
				l.Error(err.Error())
			}
		}
	}

	for _, p := range m.Packages {
		p.lint(l, m, r)
	}

	m.lintVersions(l)
}

func (p *Package) lint(l *linter, m *Module, r *Report) {
	if strings.HasPrefix(p.Package, fmt.Sprintf("%s/", stdlib.ToolchainModulePath)) &&
		m.Module != stdlib.ToolchainModulePath {
		l.Errorf(`%q should be in module "%s", not %q`, p.Package, stdlib.ToolchainModulePath, m.Module)
	}

	if !r.IsExcluded() {
		if m.VulnerableAt == "" && p.SkipFix == "" {
			l.Errorf("missing skip_fix and vulnerable_at: %q", p.Package)
		}
	}
}

func (r *Report) lintModules(l *linter, pc *proxy.Client) {
	if r.Excluded != "NOT_GO_CODE" && len(r.Modules) == 0 {
		l.Error("no modules")
	}

	for i, m := range r.Modules {
		mod := m.Module
		if mod == "" {
			mod = fmt.Sprintf("modules[%d]", i)
		}
		m.lint(l.Group(mod), r, pc)
	}
}

func (r *Report) IsFirstParty() bool {
	for _, m := range r.Modules {
		if m.IsFirstParty() {
			return true
		}
	}
	return false
}

func (m *Module) IsFirstParty() bool {
	return stdlib.IsStdModule(m.Module) || stdlib.IsCmdModule(m.Module)
}

func (e *ExcludedReason) lint(l *linter) {
	if e == nil || *e == "" {
		return
	}
	if !slices.Contains(ExcludedReasons, *e) {
		l.Errorf("excluded reason (%q) is not a valid excluded reason (accepted: %v)", *e, ExcludedReasons)
	}
}

func (m *CVEMeta) lint(l *linter, r *Report) {
	if m == nil {
		return
	}

	if m.ID == "" {
		l.Error("cve_metadata.id is required")
	} else if !cveschema5.IsCVE(m.ID) {
		l.Error("malformed cve_metadata.id identifier")
	}
	if m.CWE == "" {
		l.Error("cve_metadata.cwe is required")
	}
	if strings.Contains(m.CWE, "TODO") {
		l.Error("cve_metadata.cwe contains a TODO")
	}
	r.lintLineLength(l, "cve_metadata.cwe", m.Description)
}
