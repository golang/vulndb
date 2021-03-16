package osv

import (
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/vulndb/report"
)

type Severity int

const (
	SevNone Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var strToSev = map[string]Severity{
	// "": SevNone,
	"low":      SevLow,
	"medium":   SevMedium,
	"high":     SevHigh,
	"critical": SevCritical,
}

type Type int

const (
	TypeUnspecified Type = iota
	TypeGit
	TypeSemver
)

type Ecosystem string

const GoEcosystem Ecosystem = "go"

type Package struct {
	Name      string
	Ecosystem Ecosystem
}

type AffectsRange struct {
	Type       Type
	Introduced string
	Fixed      string
}

func (ar AffectsRange) containsSemver(v string) bool {
	if ar.Type != TypeSemver {
		return false
	}

	return (ar.Introduced == "" || semver.Compare(v, ar.Introduced) >= 0) &&
		(ar.Fixed == "" || semver.Compare(v, ar.Fixed) < 0)
}

type Affects struct {
	Ranges []AffectsRange
}

func generateAffects(versions []report.VersionRange) Affects {
	a := Affects{}
	for _, v := range versions {
		a.Ranges = append(a.Ranges, AffectsRange{
			Type:       TypeSemver,
			Introduced: v.Introduced,
			Fixed:      v.Fixed,
		})
	}
	return a
}

func (a Affects) AffectsSemver(v string) bool {
	if len(a.Ranges) == 0 {
		// No ranges implies all versions are affected
		return true
	}
	var semverRangePresent bool
	for _, r := range a.Ranges {
		if r.Type != TypeSemver {
			continue
		}
		semverRangePresent = true
		if r.containsSemver(v) {
			return true
		}
	}
	// If there were no semver ranges present we
	// assume that all semvers are affected, similarly
	// to how to we assume all semvers are affected
	// if there are no ranges at all.
	return !semverRangePresent
}

type GoSpecific struct {
	Symbols []string `json:",omitempty"`
	GOOS    []string `json:",omitempty"`
	GOARCH  []string `json:",omitempty"`
	URL     string
}

// Entry represents a OSV style JSON vulnerability database
// entry
type Entry struct {
	ID                string
	Package           Package
	Summary           string
	Details           string
	Severity          Severity
	Affects           Affects
	ReferenceURLs     []string   `json:"reference_urls,omitempty"`
	Aliases           []string   `json:",omitempty"`
	EcosystemSpecific GoSpecific `json:"ecosystem_specific,omitempty"`
	LastModified      time.Time  `json:"last_modified"`
}

func Generate(id string, url string, r report.Report) []Entry {
	entry := Entry{
		ID: id,
		Package: Package{
			Name:      r.Package,
			Ecosystem: GoEcosystem,
		},
		Summary:      "", // TODO: think if we want to populate this in reports
		Details:      r.Description,
		Affects:      generateAffects(r.Versions),
		LastModified: time.Now(),
		EcosystemSpecific: GoSpecific{
			Symbols: r.Symbols,
			GOOS:    r.OS,
			GOARCH:  r.Arch,
			URL:     url,
		},
	}

	if r.Severity != "" {
		entry.Severity = strToSev[r.Severity]
	} else {
		// Default to medium or none?
		entry.Severity = SevMedium
	}

	if r.Links.PR != "" {
		entry.ReferenceURLs = append(entry.ReferenceURLs, r.Links.PR)
	}
	if r.Links.Commit != "" {
		entry.ReferenceURLs = append(entry.ReferenceURLs, r.Links.Commit)
	}
	if r.Links.Context != nil {
		entry.ReferenceURLs = append(entry.ReferenceURLs, r.Links.Context...)
	}

	if r.CVE != "" {
		entry.Aliases = []string{r.CVE}
	}

	entries := []Entry{entry}

	// It would be better if this was just a recursive thing probably
	for _, additional := range r.AdditionalPackages {
		entryCopy := entry
		entryCopy.Package.Name = additional.Package
		entryCopy.EcosystemSpecific.Symbols = additional.Symbols
		entryCopy.Affects = generateAffects(additional.Versions)

		entries = append(entries, entryCopy)
	}

	return entries
}
