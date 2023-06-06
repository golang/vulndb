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

	"golang.org/x/exp/slices"
	"golang.org/x/mod/module"
	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/osvutils"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/stdlib"
)

func checkModVersions(modPath string, vrs []VersionRange) (err error) {
	checkVersion := func(v string) error {
		if v == "" {
			return nil
		}
		vv := "v" + v
		if err := module.Check(modPath, vv); err != nil {
			return err
		}
		canonicalPath, err := proxy.CanonicalModulePath(modPath, vv)
		if err != nil {
			return fmt.Errorf("unable to retrieve canonical module path from proxy: %s", err)
		}
		if canonicalPath != modPath {
			return fmt.Errorf("invalid module path %q at version %q (canonical path is %q)", modPath, v, canonicalPath)
		}
		return nil
	}
	for _, vr := range vrs {
		for _, v := range []string{vr.Introduced, vr.Fixed} {
			if err := checkVersion(v); err != nil {
				return fmt.Errorf("bad version %q: %s", v, err)
			}
		}
	}
	return nil
}

func (m *Module) lintStdLib(addPkgIssue func(string)) {
	if len(m.Packages) == 0 {
		addPkgIssue("missing package")
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			addPkgIssue("missing package")
		}
	}
}

func (m *Module) lintThirdParty(addPkgIssue func(string)) {
	if m.Module == "" {
		addPkgIssue("missing module")
		return
	}
	if err := checkModVersions(m.Module, m.Versions); err != nil {
		addPkgIssue(err.Error())
	}
	for _, p := range m.Packages {
		if p.Package == "" {
			addPkgIssue("missing package")
			continue
		}
		if !strings.HasPrefix(p.Package, m.Module) {
			addPkgIssue("module must be a prefix of package")
		}
		if err := module.CheckImportPath(p.Package); err != nil {
			addPkgIssue(err.Error())
		}
	}
}

func (m *Module) lintVersions(addPkgIssue func(string)) {
	ranges := AffectedRanges(m.Versions)
	if v := m.VulnerableAt; v != "" {
		affected, err := osvutils.AffectsSemver(ranges, v)
		if err != nil {
			addPkgIssue(fmt.Sprintf("version issue: %s", err))
		} else if !affected {
			addPkgIssue(fmt.Sprintf("vulnerable_at version %s is not inside vulnerable range", v))
		}
	} else {
		if err := osvutils.ValidateRanges(ranges); err != nil {
			addPkgIssue(fmt.Sprintf("version issue: %s", err))
		}
	}
}

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func (r *Report) lintCVEs(addIssue func(string)) {
	if len(r.CVEs) > 0 && r.CVEMetadata != nil && r.CVEMetadata.ID != "" {
		// TODO: consider removing one of these fields from the Report struct.
		addIssue("only one of cve and cve_metadata.id should be present")
	}

	for _, cve := range r.CVEs {
		if !cveRegex.MatchString(cve) {
			addIssue("malformed cve identifier")
		}
	}

	if r.CVEMetadata != nil {
		if r.CVEMetadata.ID == "" {
			addIssue("cve_metadata.id is required")
		} else if !cveRegex.MatchString(r.CVEMetadata.ID) {
			addIssue("malformed cve_metadata.id identifier")
		}
		if r.CVEMetadata.CWE == "" {
			addIssue("cve_metadata.cwe is required")
		}
	}
}

func (r *Report) lintLineLength(field, content string, addIssue func(string)) {
	const maxLineLength = 100
	for _, line := range strings.Split(content, "\n") {
		if len(line) <= maxLineLength {
			continue
		}
		if !strings.Contains(line, " ") {
			continue // A single long word is OK.
		}
		addIssue(fmt.Sprintf("%v contains line > %v characters long: %q", field, maxLineLength, line))
		return
	}
}

// Regex patterns for standard links.
var (
	prRegex       = regexp.MustCompile(`https://go.dev/cl/\d+`)
	commitRegex   = regexp.MustCompile(`https://go.googlesource.com/[^/]+/\+/([^/]+)`)
	issueRegex    = regexp.MustCompile(`https://go.dev/issue/\d+`)
	announceRegex = regexp.MustCompile(`https://groups.google.com/g/golang-(announce|dev|nuts)/c/([^/]+)`)

	nistRegex  = regexp.MustCompile(`^https://nvd.nist.gov/vuln/detail/(CVE-.*)$`)
	ghsaRegex  = regexp.MustCompile(`^https://github.com/.*/(GHSA-[^/]+)$`)
	mitreRegex = regexp.MustCompile(`^https://cve.mitre.org/.*(CVE-[\d\-]+)$`)
)

// Checks that the "links" section of a Report for a package in the
// standard library contains all necessary links, and no third-party links.
func (r *Report) lintStdLibLinks(addIssue func(string)) {
	var (
		hasFixLink      = false
		hasReportLink   = false
		hasAnnounceLink = false
	)
	for _, ref := range r.References {
		switch ref.Type {
		case osv.ReferenceTypeAdvisory:
			addIssue(fmt.Sprintf("%q: advisory reference should not be set for first-party issues", ref.URL))
		case osv.ReferenceTypeFix:
			hasFixLink = true
			if !prRegex.MatchString(ref.URL) && !commitRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: fix reference should match %q or %q", ref.URL, prRegex, commitRegex))
			}
		case osv.ReferenceTypeReport:
			hasReportLink = true
			if !issueRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: report reference should match %q", ref.URL, issueRegex))
			}
		case osv.ReferenceTypeWeb:
			if !announceRegex.MatchString(ref.URL) {
				addIssue(fmt.Sprintf("%q: web references should only contain announcement links matching %q", ref.URL, announceRegex))
			} else {
				hasAnnounceLink = true
			}
		}
	}
	if !hasFixLink {
		addIssue("references should contain at least one fix")
	}
	if !hasReportLink {
		addIssue("references should contain at least one report")
	}
	if !hasAnnounceLink {
		addIssue(fmt.Sprintf("references should contain an announcement link matching %q", announceRegex))
	}
}

func (r *Report) lintLinks(addIssue func(string)) {
	advisoryCount := 0
	for _, ref := range r.References {
		if !slices.Contains(osv.ReferenceTypes, ref.Type) {
			addIssue(fmt.Sprintf("%q is not a valid reference type", ref.Type))
		}
		l := ref.URL
		if _, err := url.ParseRequestURI(l); err != nil {
			addIssue(fmt.Sprintf("%q is not a valid URL", l))
		}
		if fixed := fixURL(l); fixed != l {
			addIssue(fmt.Sprintf("unfixed url: %q should be %q", l, fixURL(l)))
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
			for _, re := range []*regexp.Regexp{nistRegex, mitreRegex, ghsaRegex} {
				if m := re.FindStringSubmatch(ref.URL); len(m) > 0 {
					id := m[1]
					if slices.Contains(r.CVEs, id) || slices.Contains(r.GHSAs, id) {
						addIssue(fmt.Sprintf("redundant non-advisory reference to %v", id))
					}
				}
			}
		}
	}
	if advisoryCount > 1 {
		addIssue("references should contain at most one advisory link")
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
func (r *Report) Lint() []string {
	var issues []string

	addIssue := func(iss string) {
		issues = append(issues, iss)
	}

	if r.ID == "" {
		addIssue("missing ID")
	}

	if r.IsExcluded() {
		if !slices.Contains(ExcludedReasons, r.Excluded) {
			addIssue(fmt.Sprintf("excluded reason (%q) is not a valid excluded reason (accepted: %v)", r.Excluded, ExcludedReasons))
		}
		if r.Excluded != "NOT_GO_CODE" && len(r.Modules) == 0 {
			addIssue("no modules")
		}
		if len(r.CVEs) == 0 && len(r.GHSAs) == 0 {
			addIssue("excluded report must have at least one associated CVE or GHSA")
		}
	} else {
		if len(r.Modules) == 0 {
			addIssue("no modules")
		}
		if r.Description == "" {
			addIssue("missing description")
		}
		if r.Summary == "" {
			addIssue("missing summary")
		}
		if strings.HasPrefix(r.Summary, "TODO") {
			addIssue("summary contains a TODO")
		}
		if l := len(r.Summary); l > 100 {
			addIssue(fmt.Sprintf("summary is too long: %d characters (max 100)", l))
		}
		if strings.HasSuffix(r.Summary, ".") {
			addIssue("summary should not end in a period (should be a phrase, not a sentence)")
		}
	}

	isFirstParty := false
	for i, m := range r.Modules {
		addPkgIssue := func(iss string) {
			addIssue(fmt.Sprintf("modules[%v]: %v", i, iss))
		}
		if m.IsFirstParty() {
			isFirstParty = true
			m.lintStdLib(addPkgIssue)
		} else {
			m.lintThirdParty(addPkgIssue)
		}
		for _, p := range m.Packages {
			if strings.HasPrefix(p.Package, fmt.Sprintf("%s/", stdlib.ToolchainModulePath)) && m.Module != stdlib.ToolchainModulePath {
				addPkgIssue(fmt.Sprintf(`%q should be in module "%s", not %q`, p.Package, stdlib.ToolchainModulePath, m.Module))
			}

			if !r.IsExcluded() {
				if m.VulnerableAt == "" && p.SkipFix == "" {
					addPkgIssue(fmt.Sprintf("missing skip_fix and vulnerable_at: %q", p.Package))
				}
			}
		}

		m.lintVersions(addPkgIssue)
	}

	r.lintLineLength("description", r.Description, addIssue)
	if r.CVEMetadata != nil {
		r.lintLineLength("cve_metadata.description", r.CVEMetadata.Description, addIssue)
	}
	r.lintCVEs(addIssue)

	if isFirstParty && !r.IsExcluded() {
		r.lintStdLibLinks(addIssue)
	}

	r.lintLinks(addIssue)

	return issues
}

func (m *Module) IsFirstParty() bool {
	return stdlib.IsStdModule(m.Module) || stdlib.IsCmdModule(m.Module)
}
