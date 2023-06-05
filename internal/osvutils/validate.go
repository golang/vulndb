// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package osvutils provides utilities for working with Go OSV entries.
// It is separated from package osv because that package
// promises to only import from the standard library.
package osvutils

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/osv"
	"golang.org/x/vulndb/internal/version"
)

// Validate errors if there are any problems with the OSV Entry.
// It is used to validate OSV entries before publishing them to the
// Go vulnerability database, and has stricter requirements than
// the general OSV format.
func Validate(e *osv.Entry) (err error) {
	derrors.Wrap(&err, "Validate(%s)", e.ID)
	return validate(e, true)
}

// ValidateExceptTimestamps errors if there are any problems with the
// OSV Entry, with the exception of the timestamps (published, modified and
// withdrawn) which are not checked.
// This is used to validate entries at CL submit time, before their timestamps
// are corrected.
func ValidateExceptTimestamps(e *osv.Entry) (err error) {
	derrors.Wrap(&err, "ValidateExceptTimestamps(%s)", e.ID)
	return validate(e, false)
}

var (
	// Errors for incorrect timestamps.
	errNoModified             = errors.New("modified time must be non-zero")
	errNoPublished            = errors.New("published time must be non-zero")
	errPublishedAfterModified = errors.New("published time cannot be after modified time")

	// Errors for missing fields.
	errNoID                = errors.New("id field is empty")
	errNoSchemaVersion     = errors.New("schema_version field is empty")
	errNoDetails           = errors.New("details field is empty")
	errNoAffected          = errors.New("affected field is empty")
	errNoReferences        = errors.New("references field is empty")
	errNoDatabaseSpecific  = errors.New("database_specific field is empty")
	errNoModule            = errors.New("affected field missing module path")
	errNotGoEcosystem      = errors.New("affected ecosystem is not Go")
	errNoRanges            = errors.New("affected field contains no ranges")
	errNoEcosystemSpecific = errors.New("affected field contains no ecosystem_specific field")
	errNoPackages          = errors.New("affected.ecosystem_specific field has no packages")
	errNoPackagePath       = errors.New("affected.ecosystem_specific.imports field has no package path")

	// Errors for invalid fields.
	errInvalidAlias           = errors.New("alias must be CVE or GHSA ID")
	errInvalidPkgsiteURL      = errors.New("database_specific.URL must be a link to https://pkg.go.dev/vuln/<Go id>")
	errInvalidPackagePath     = errors.New("package path must be prefixed by module path")
	errTooManyRanges          = errors.New("each module should have exactly one version range")
	errRangeTypeNotSemver     = errors.New("range type must be SEMVER")
	errNoRangeEvents          = errors.New("range must contain one or more events")
	errOutOfOrderRange        = errors.New("introduced and fixed versions must alternate")
	errUnsortedRange          = errors.New("range events must be in strictly ascending order")
	errNoIntroducedOrFixed    = errors.New("introduced or fixed must be set")
	errBothIntroducedAndFixed = errors.New("introduced and fixed cannot both be set in same event")
	errInvalidSemver          = errors.New("invalid or non-canonical semver version")

	// Regular expressions.
	ghsaRegex        = regexp.MustCompile(`^GHSA-[^-]{4}-[^-]{4}-[^-]{4}$`)
	cveRegex         = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	pkgsiteLinkRegex = regexp.MustCompile(`^https://pkg.go.dev/vuln/GO-\d{4}-\d{4,}$`)
)

func validate(e *osv.Entry, checkTimestamps bool) (err error) {
	if checkTimestamps {
		switch {
		case e.Modified.IsZero():
			return errNoModified
		case e.Published.IsZero():
			return errNoPublished
		case e.Published.After(e.Modified.Time):
			return fmt.Errorf("%w (published=%s, modified=%s)", errPublishedAfterModified, e.Published, e.Modified)
		}
	}

	// Check for missing required fields.
	switch {
	case e.ID == "":
		return errNoID
	case e.SchemaVersion == "":
		return errNoSchemaVersion
	case e.Details == "":
		return errNoDetails
	case len(e.Affected) == 0:
		return errNoAffected
	case len(e.References) == 0:
		return errNoReferences
	case e.DatabaseSpecific == nil:
		return errNoDatabaseSpecific
	}

	for _, a := range e.Affected {
		if err := validateAffected(&a); err != nil {
			return err
		}
	}
	for _, alias := range e.Aliases {
		if !ghsaRegex.MatchString(alias) && !cveRegex.MatchString(alias) {
			return fmt.Errorf("%w (found alias %s)", errInvalidAlias, alias)
		}
	}

	return validateDatabaseSpecific(e.DatabaseSpecific)
}

func validateAffected(a *osv.Affected) error {
	switch {
	case a.Module.Path == "":
		return errNoModule
	case a.Module.Ecosystem != osv.GoEcosystem:
		return errNotGoEcosystem
	}

	if err := ValidateRanges(a.Ranges); err != nil {
		return err
	}

	return validateEcosystemSpecific(a.EcosystemSpecific, a.Module.Path)
}

func ValidateRanges(ranges []osv.Range) error {
	switch {
	case len(ranges) == 0:
		return errNoRanges
	case len(ranges) > 1:
		return fmt.Errorf("%w (found %d ranges)", errTooManyRanges, len(ranges))
	}

	return validateRange(&ranges[0])
}

func validateRange(r *osv.Range) error {
	switch {
	case r.Type != osv.RangeTypeSemver:
		return fmt.Errorf("%w (found range type %q)",
			errRangeTypeNotSemver, r.Type)
	case len(r.Events) == 0:
		return errNoRangeEvents
	}

	// Check that all the events are valid and sorted in ascending order.
	prev, err := parseRangeEvent(&r.Events[0])
	if err != nil {
		return err
	}
	for _, event := range r.Events[1:] {
		current, err := parseRangeEvent(&event)
		if err != nil {
			return fmt.Errorf("invalid range event: %w", err)
		}
		// Introduced and fixed versions must alternate.
		if current.introduced == prev.introduced {
			return errOutOfOrderRange
		}
		if !less(prev.v, current.v) {
			return fmt.Errorf("%w (found %s>=%s)", errUnsortedRange, prev.v, current.v)
		}
		prev = current
	}

	return nil
}

func less(v, w string) bool {
	// Ensure that version 0 is always lowest.
	if v == "0" {
		return true
	}
	if w == "0" {
		return false
	}
	return version.Before(v, w)
}

type event struct {
	v          string
	introduced bool
}

func parseRangeEvent(e *osv.RangeEvent) (*event, error) {
	introduced, fixed := e.Introduced, e.Fixed

	var v string
	var isIntroduced bool
	switch {
	case introduced == "" && fixed == "":
		return nil, errNoIntroducedOrFixed
	case introduced != "" && fixed != "":
		return nil, errBothIntroducedAndFixed
	case introduced == "0":
		return &event{v: "0", introduced: true}, nil
	case introduced != "":
		v = introduced
		isIntroduced = true
	case fixed != "":
		v = fixed
		isIntroduced = false
	}

	if !version.IsValid(v) || v != version.Canonical(v) {
		return nil, fmt.Errorf("%w (found %s)", errInvalidSemver, v)
	}

	return &event{v: v, introduced: isIntroduced}, nil
}

func validateEcosystemSpecific(es *osv.EcosystemSpecific, module string) error {
	if es == nil {
		return errNoEcosystemSpecific
	}

	if len(es.Packages) == 0 {
		return errNoPackages
	}

	for _, pkg := range es.Packages {
		if pkg.Path == "" {
			return errNoPackagePath
		}
		// Package path must be prefixed by module path unless it is
		// in the Go standard library or toolchain.
		if (module != osv.GoStdModulePath && module != osv.GoCmdModulePath) &&
			!strings.HasPrefix(pkg.Path, module) {
			return fmt.Errorf("%w (found module=%q, package=%q)", errInvalidPackagePath, module, pkg.Path)
		}
	}

	return nil
}

func validateDatabaseSpecific(d *osv.DatabaseSpecific) error {
	if !pkgsiteLinkRegex.MatchString(d.URL) {
		return fmt.Errorf("%w (found URL %q)", errInvalidPkgsiteURL, d.URL)
	}
	return nil
}
