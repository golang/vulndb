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
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/stdlib"
)

func (m *Module) checkModVersions(pc *proxy.Client) error {
	if ok := pc.ModuleExists(m.Module); !ok {
		return fmt.Errorf("module %s not known to proxy", m.Module)
	}

	_, notFound, nonCanonical := m.classifyVersions(pc)

	var sb strings.Builder
	nf, nc := len(notFound), len(nonCanonical)
	if nf > 0 {
		if nf == 1 {
			sb.WriteString(fmt.Sprintf("version %s does not exist", notFound[0]))
		} else {
			sb.WriteString(fmt.Sprintf("%d versions do not exist: %s", nf, notFound))
		}
	}
	if nc > 0 {
		if nf > 0 {
			sb.WriteString(" and ")
		}
		sb.WriteString(fmt.Sprintf("module is not canonical at %d version(s): %s", nc, strings.Join(nonCanonical, ", ")))
	}
	if s := sb.String(); s != "" {
		return errors.New(s)
	}
	return nil
}

func (vs Versions) String() string {
	var s []string
	for _, v := range vs {
		s = append(s, v.Version)
	}
	return strings.Join(s, ", ")
}

func (m *Module) classifyVersions(pc *proxy.Client) (found, notFound Versions, nonCanonical []string) {
	for _, vr := range m.Versions {
		v := vr.Version
		c, err := pc.CanonicalModulePath(m.Module, v)
		if err != nil {
			notFound = append(notFound, vr)
			continue
		}
		found = append(found, vr)
		if c != m.Module {
			nonCanonical = append(nonCanonical, fmt.Sprintf("%s (canonical:%s)", v, c))
		}
	}
	return found, notFound, nonCanonical
}

var missing = "missing"

func (m *Module) lintVersions(l *linter) {
	vl := l.Group("versions")
	ranges, err := m.Versions.ToSemverRanges()
	if err != nil {
		vl.Errorf("invalid version(s): %s", err)
	}
	if v := m.VulnerableAt; v != nil {
		affected, err := osvutils.AffectsSemver(ranges, v.Version)
		if err != nil {
			vl.Error(err)
		} else if !affected {
			l.Group("vulnerable_at").Errorf("%s is not inside vulnerable range", v.Version)
		}
	} else {
		if err := osvutils.ValidateRanges(ranges); err != nil {
			vl.Error(err)
		}
	}
}

func (r *Report) lintCVEs(l *linter) {
	for i, cve := range r.CVEs {
		if !idstr.IsCVE(cve) {
			l.Group(name("cves", i, cve)).Error("malformed cve identifier")
		}
	}
}

func (r *Report) lintGHSAs(l *linter) {
	for i, g := range r.GHSAs {
		if !idstr.IsGHSA(g) {
			l.Group(name("ghsas", i, g)).Errorf("%s is not a valid GHSA", g)
		}
	}
}

func name(field string, index int, name string) string {
	fieldIndex := fmt.Sprintf("%s[%d]", field, index)
	if name != "" {
		return fmt.Sprintf("%s %q", fieldIndex, name)
	}
	return fieldIndex
}

func (r *Report) lintRelated(l *linter) {
	if len(r.Related) == 0 {
		// Not required.
		return
	}

	aliases := r.Aliases()
	for i, related := range r.Related {
		rl := l.Group(name("related", i, related))
		// In most cases, the related list is very short, so there's no
		// need create a map of aliases.
		if slices.Contains(aliases, related) {
			rl.Error("also listed among aliases")
		}
		if !idstr.IsIdentifier(related) {
			rl.Error("not a recognized identifier (CVE, GHSA or Go ID)")
		}
	}
}

const maxLineLength = 80

func (r *Report) lintLineLength(l *linter, content string) {
	for _, line := range strings.Split(content, "\n") {
		if len(line) <= maxLineLength {
			continue
		}
		if !strings.Contains(line, " ") {
			continue // A single long word is OK.
		}
		l.Errorf("contains line > %v characters long: %q", maxLineLength, line)
		return
	}
}

// Regex patterns for standard links.
var (
	prRegex       = regexp.MustCompile(`https://go.dev/cl/\d+`)
	commitRegex   = regexp.MustCompile(`https://go.googlesource.com/[^/]+/\+/([^/]+)`)
	issueRegex    = regexp.MustCompile(`https://go.dev/issue/\d+`)
	announceRegex = regexp.MustCompile(`https://groups.google.com/g/golang-(announce|dev|nuts)/c/([^/]+)`)
)

func (ref *Reference) lint(l *linter, r *Report) {
	// Checks specific to first-party reports.
	if r.IsFirstParty() {
		switch ref.Type {
		case osv.ReferenceTypeAdvisory:
			l.Errorf("%q: advisory reference must not be set for first-party issues", ref.URL)
		case osv.ReferenceTypeFix:
			if !prRegex.MatchString(ref.URL) && !commitRegex.MatchString(ref.URL) {
				l.Errorf("%q: fix reference must match %q or %q", ref.URL, prRegex, commitRegex)
			}
		case osv.ReferenceTypeReport:
			if !issueRegex.MatchString(ref.URL) {
				l.Errorf("%q: report reference must match regex %q", ref.URL, issueRegex)
			}
		case osv.ReferenceTypeWeb:
			if !announceRegex.MatchString(ref.URL) {
				l.Errorf("%q: web reference must match regex %q", ref.URL, announceRegex)
			}
		}
	}

	if !slices.Contains(osv.ReferenceTypes, ref.Type) {
		l.Errorf("invalid reference type %q", ref.Type)
	}
	u := ref.URL
	if _, err := url.ParseRequestURI(u); err != nil {
		l.Error("invalid URL")
	}
	if fixed := fixURL(u); fixed != u {
		l.Errorf("should be %q (can be auto-fixed)", fixURL(u))
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
		if id, ok := idstr.IsAdvisoryForOneOf(ref.URL, r.Aliases()); ok {
			l.Errorf("redundant non-advisory reference to %v", id)
		}
	}
}

// IsOriginal returns whether the source of this report is
// definitely the Go security team. (Many older reports do not have this
// metadata so other heuristics would have to be used).
func (r *Report) IsOriginal() bool {
	return r.SourceMeta != nil && r.SourceMeta.ID == sourceGoTeam
}

func (r *Report) IsReviewed() bool {
	return r.ReviewStatus == Reviewed
}

func (r *Report) IsUnreviewed() bool {
	return !r.IsReviewed() && !r.IsExcluded()
}

func (r *Report) lintReferences(l *linter) {
	for i, ref := range r.References {
		rl := l.Group(name("references", i, ref.URL))
		ref.lint(rl, r)
	}

	rl := l.Group("references")

	// Check advisory count.
	switch c := r.countAdvisories(); {
	case c == 0 && r.needsAdvisory():
		rl.Errorf("missing advisory (required because report has no description or is %v)", Unreviewed)
	case c > 1 && r.IsReviewed():
		rl.Errorf("too many advisories (found %d, want <=1)", c)
	}

	// First-party reports have stricter requirements for references.
	if !r.IsExcluded() && r.IsFirstParty() {
		var hasFixLink, hasReportLink, hasAnnounceLink bool
		for _, ref := range r.References {
			switch ref.Type {
			case osv.ReferenceTypeFix:
				hasFixLink = true
			case osv.ReferenceTypeReport:
				hasReportLink = true
			case osv.ReferenceTypeWeb:
				if announceRegex.MatchString(ref.URL) {
					hasAnnounceLink = true
				}
			}
		}
		if !hasFixLink {
			rl.Error("must contain at least one fix")
		}
		if !hasReportLink {
			rl.Error("must contain at least one report")
		}
		if !hasAnnounceLink {
			rl.Errorf("must contain an announcement link matching regex %q", announceRegex)
		}
	}
}

func (r *Report) lintReviewStatus(l *linter) {
	if r.IsExcluded() {
		return
	}

	if r.ReviewStatus == 0 || !osv.ReviewStatus(r.ReviewStatus).IsValid() {
		l.Errorf("review_status missing or invalid (must be one of [%s])", strings.Join(osv.ReviewStatusValues(), ", "))
	}
}

func (r *Report) lintSource(l *linter) {
	if r.SourceMeta == nil {
		return
	}
	if r.IsUnreviewed() && r.SourceMeta.ID == sourceGoTeam {
		l.Errorf("source: if id=%s, report must be %s", sourceGoTeam, Reviewed)
	}
}

func (r *Report) countAdvisories() int {
	advisoryCount := 0
	for _, ref := range r.References {
		if ref.Type == osv.ReferenceTypeAdvisory {
			advisoryCount++
		}
	}
	return advisoryCount
}

func (r *Report) needsAdvisory() bool {
	switch {
	case r.IsExcluded(), r.CVEMetadata != nil, r.IsFirstParty():
		return false
	case r.Description == "", r.IsUnreviewed():
		return true
	}
	return false
}

func (d *Description) lint(l *linter, r *Report) {
	desc := d.String()

	checkNoMarkdown(l, desc)
	r.lintLineLength(l, desc)
	if !r.IsExcluded() && desc == "" {
		if r.CVEMetadata != nil {
			l.Error("missing (reports with Go CVEs must have a description)")
		}
	}
}

const summaryMaxLen = 125

func (s *Summary) lint(l *linter, r *Report) {
	summary := s.String()
	if len(summary) == 0 {
		if !r.IsExcluded() {
			l.Error(missing)
		}
		// Nothing else to lint.
		return
	}
	if hasTODO(summary) {
		l.Error(hasTODOErr)
		// No need to keep linting, as this is likely a placeholder value.
		return
	}

	// Non-reviewed reports don't need to meet strict requirements.
	if r.IsUnreviewed() {
		return
	}

	checkNoMarkdown(l, summary)
	if ln := len(summary); ln > summaryMaxLen {
		l.Errorf("too long (found %d characters, want <=%d)", ln, summaryMaxLen)
	}
	if strings.HasSuffix(summary, ".") {
		l.Error("must not end in a period (should be a phrase, not a sentence)")
	}
	if !startsWithUpper(summary) {
		l.Error("must begin with a capital letter")
	}

	// Summary must contain one of the listed module or package
	// paths. (Except in the "std" module, where a specific package
	// must be mentioned).
	// If there are no such paths listed in the report at all,
	// another lint will complain, so reduce noise by not erroring here.
	if paths := r.nonStdPaths(); len(paths) > 0 {
		if ok := containsPath(summary, paths); !ok {
			l.Errorf("must contain an affected module or package path (e.g. %q)", paths[0])
		}
	}
}

func startsWithUpper(s string) bool {
	for i, r := range s {
		if i != 0 {
			return true
		}
		if !unicode.IsUpper(r) {
			return false
		}
	}
	return false
}

// containsPath returns whether the summary contains one of
// the paths in paths.
// As a special case, if the summary contains a word that contains a "/"
// and is a prefix of a path, the function returns true. This gives us a
// workaround for reports that affect a lot of modules and/or have very long
// module paths.
func containsPath(summary string, paths []string) bool {
	if len(paths) == 0 {
		return false
	}

	for _, possiblePath := range strings.Fields(summary) {
		possiblePath := strings.TrimRight(possiblePath, ":,.")
		for _, path := range paths {
			if possiblePath == path {
				return true
			}
			if strings.Contains(possiblePath, "/") &&
				strings.HasPrefix(path, possiblePath) {
				return true
			}
		}
	}

	return false
}

// nonStdPaths returns all module and package paths (except "std")
// mentioned in the report.
func (r *Report) nonStdPaths() (paths []string) {
	for _, m := range r.Modules {
		if m.Module != "" && m.Module != stdlib.ModulePath {
			paths = append(paths, m.Module)
		}
		for _, p := range m.Packages {
			if p.Package != "" {
				paths = append(paths, p.Package)
			}
		}
	}
	return paths
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

	if excluded && dir != excludedFolder {
		return fmt.Errorf("%w (want %s, found %s)", errWrongDir, excludedFolder, dir)
	}

	if !excluded && dir != reportsFolder {
		return fmt.Errorf("%w (want %s, found %s)", errWrongDir, reportsFolder, dir)
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
	r.deleteNotes(NoteTypeLint)

	if lints := r.Lint(pc); len(lints) > 0 {
		slices.Sort(lints)
		for _, lint := range lints {
			r.AddNote(NoteTypeLint, lint)
		}
		return true
	}

	return false
}

func (r *Report) deleteNotes(t NoteType) {
	r.Notes = slices.DeleteFunc(r.Notes, func(n *Note) bool {
		return n.Type == t
	})
}

func (r *Report) AddNote(t NoteType, format string, v ...any) {
	n := &Note{
		Body: fmt.Sprintf(format, v...),
		Type: t,
	}
	// Don't add the same note twice.
	for _, nn := range r.Notes {
		if nn.Type == n.Type && nn.Body == n.Body {
			return
		}
	}
	r.Notes = append(r.Notes, n)
}

// LintOffline performs all lint checks that don't require a network connection.
func (r *Report) LintOffline() []string {
	return r.lint(nil)
}

func (r *Report) lint(pc *proxy.Client) []string {
	l := NewLinter("")

	if r.ID == "" {
		l.Group("id").Error(missing)
	}

	r.Summary.lint(l.Group("summary"), r)
	r.Description.lint(l.Group("description"), r)
	r.Excluded.lint(l.Group("excluded"))

	r.lintModules(l, pc)

	r.CVEMetadata.lint(l.Group("cve_metadata"), r)

	if r.IsExcluded() && len(r.Aliases()) == 0 {
		l.Group("cves,ghsas").Error()
	}

	r.lintCVEs(l)
	r.lintGHSAs(l)
	r.lintRelated(l)

	r.lintReferences(l)
	r.lintReviewStatus(l)
	r.lintSource(l)

	if r.hasTODOs() {
		l.Error("contains one or more TODOs")
	}

	return l.Errors()
}

func (m *Module) lint(l *linter, r *Report, pc *proxy.Client) {
	if m.SkipLint {
		return
	}

	if m.Module == "" {
		l.Error("no module name")
	}

	if !r.IsExcluded() && !m.IsFirstParty() && pc != nil {
		if err := m.checkModVersions(pc); err != nil {
			l.Error(err)
		}
	}

	if m.IsFirstParty() && len(m.Packages) == 0 {
		l.Error("no packages")
	}

	for i, p := range m.Packages {
		p.lint(l.Group(name("packages", i, p.Package)), m, r)
	}

	if r.IsReviewed() {
		if u := len(m.UnsupportedVersions); u > 0 {
			l.Group("unsupported_versions").Errorf("found %d (want none)", u)
		}
	}

	m.lintVersions(l)
}

func (p *Package) lint(l *linter, m *Module, r *Report) {
	if p.Package == "" {
		l.Error("no package name")
	} else {
		if m.Module != stdlib.ModulePath {
			if !strings.HasPrefix(p.Package, m.Module) {
				l.Error("module must be a prefix of package")
			}
		} else {
			if p.Package == "runtime" && len(p.Symbols) != 0 {
				l.Errorf("runtime package must have no symbols (found %d)", len(p.Symbols))
			}
			// As a special case, check for "cmd/" packages that are
			// mistakenly placed in the "std" module.
			if strings.HasPrefix(p.Package, stdlib.ToolchainModulePath) {
				l.Error("must be in module cmd")
			}
		}

		if !m.IsFirstParty() {
			if err := module.CheckImportPath(p.Package); err != nil {
				l.Error(err)
			}
		}
	}

	if !r.IsExcluded() {
		if m.VulnerableAt == nil && p.SkipFixSymbols == "" {
			l.Error("at least one of vulnerable_at and skip_fix must be set")
		}
	}
}

func (r *Report) lintModules(l *linter, pc *proxy.Client) {
	if r.Excluded != "NOT_GO_CODE" && len(r.Modules) == 0 {
		l.Group("modules").Error(missing)
	}

	for i, m := range r.Modules {
		m.lint(l.Group(name("modules", i, m.Module)), r, pc)
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

	il := l.Group("id")
	if m.ID == "" {
		il.Error(missing)
	} else if !idstr.IsCVE(m.ID) {
		il.Error("not a valid CVE")
	}

	cl := l.Group("cwe")
	if m.CWE == "" {
		cl.Error(missing)
	}
	if hasTODO(m.CWE) {
		cl.Error(hasTODOErr)
	}

	r.lintLineLength(l.Group("description"), m.Description)
}

var hasTODOErr = "contains a TODO"

func hasTODO(s string) bool {
	return strings.Contains(s, "TODO")
}

// Regular expressions for markdown-style elements that shouldn't
// be in our descriptions/summaries.
var (
	backtickRE = regexp.MustCompile("(`.*`)")
	linkRE     = regexp.MustCompile(`(\[.*\]\(.*\))`)
	headingRE  = regexp.MustCompile(`(#+ )`)
)

func checkNoMarkdown(l *linter, s string) {
	for _, re := range []*regexp.Regexp{backtickRE, linkRE, headingRE} {
		matches := re.FindStringSubmatch(s)
		if len(matches) > 0 {
			l.Errorf("possible markdown formatting (found %s)", matches[1])
		}
	}
}

func (r *Report) hasTODOs() bool {
	is := hasTODO
	any := func(ss []string) bool { return slices.IndexFunc(ss, is) >= 0 }

	if is(string(r.Excluded)) {
		return true
	}
	for _, m := range r.Modules {
		if is(m.Module) {
			return true
		}
		for _, v := range m.Versions {
			if is(v.Version) {
				return true
			}
		}
		if m.VulnerableAt != nil && is(m.VulnerableAt.Version) {
			return true
		}
		for _, p := range m.Packages {
			// don't check p.SkipFix, this may contain TODOs for historical reasons
			if is(p.Package) || any(p.Symbols) || any(p.DerivedSymbols) {
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
	return is(r.Description.String()) || any(r.Credits)
}
