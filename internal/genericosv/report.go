// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genericosv

import (
	"fmt"
	"strings"

	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/report"
)

var _ report.Source = &Entry{}

// ToReport converts OSV into a Go Report with the given ID.
func (osv *Entry) ToReport(string) *report.Report {
	r := &report.Report{
		Summary:     report.Summary(osv.Summary),
		Description: report.Description(osv.Details),
	}
	addAlias := func(alias string) {
		switch {
		case idstr.IsCVE(alias):
			r.CVEs = append(r.CVEs, alias)
		case idstr.IsGHSA(alias):
			r.GHSAs = append(r.GHSAs, alias)
		case idstr.IsGoID(alias):
			// ignore Go IDs
		default:
			r.UnknownAliases = append(r.UnknownAliases, alias)
		}
	}
	addAlias(osv.ID)
	for _, alias := range osv.Aliases {
		addAlias(alias)
	}

	r.Modules = affectedToModules(osv.Affected)

	for _, ref := range osv.References {
		r.References = append(r.References, convertRef(ref))
	}

	r.Credits = convertCredits(osv.Credits)
	return r
}

func (osv *Entry) SourceID() string {
	return osv.ID
}

func affectedToModules(as []Affected) []*report.Module {
	var modules []*report.Module
	for _, a := range as {
		if a.Package.Ecosystem != EcosystemGo {
			continue
		}

		versions, unsupportedVersions := convertVersions(a.Ranges)
		modules = append(modules, &report.Module{
			Module:              a.Package.Name,
			Versions:            versions,
			UnsupportedVersions: unsupportedVersions,
		})
	}
	return modules
}

func convertVersions(rs []Range) (vs report.Versions, unsupported report.Versions) {
	for _, r := range rs {
		for _, e := range r.Events {
			if e.Introduced != "" || e.Fixed != "" {
				var vr *report.Version
				switch {
				case e.Introduced == "0":
					continue
				case e.Introduced != "":
					vr = report.Introduced(e.Introduced)
				case e.Fixed != "":
					vr = report.Fixed(e.Fixed)
				}
				vs = append(vs, vr)
				continue
			}

			uv := new(report.Version)
			switch {
			case e.LastAffected != "":
				uv.Version = e.LastAffected
				uv.Type = "last_affected"
			case e.Limit != "":
				uv.Version = e.Limit
				uv.Type = "limit"
			default:
				uv.Version = fmt.Sprint(e)
				uv.Type = "unknown"
			}
			unsupported = append(unsupported, uv)
		}
	}
	return vs, unsupported
}

func convertRef(ref Reference) *report.Reference {
	return &report.Reference{
		Type: osv.ReferenceType(ref.Type),
		URL:  ref.URL,
	}
}

func convertCredits(cs []Credit) []string {
	var credits []string
	for _, c := range cs {
		credit := c.Name
		if len(c.Contact) != 0 {
			credit = fmt.Sprintf("%s (%s)", c.Name, strings.Join(c.Contact, ","))
		}
		credits = append(credits, credit)
	}
	return credits
}
