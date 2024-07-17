// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/vulndb/internal/pkgsite"
)

// CheckPackages returns an error if any of the packages listed in the report
// do not exist (according to pkgsite).
func (r *Report) CheckPackages(ctx context.Context, pkc *pkgsite.Client) (errs error) {
	for _, m := range r.Modules {
		for _, p := range m.Packages {
			var v string
			if m.VulnerableAt != nil {
				v = m.VulnerableAt.Version
			}
			if err := p.check(ctx, v, pkc); err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	return errs
}

var errPackageNotExist = errors.New("package does not exist")

func (p *Package) check(ctx context.Context, ver string, pkc *pkgsite.Client) error {
	existsAtLatest, err := pkc.KnownModule(ctx, p.Package)
	if err != nil {
		return err
	}
	if existsAtLatest {
		return nil
	}
	// If the package doesn't exist at latest, it might have been deleted.
	// Check if it existed at the given version.
	// This is a fallback instead of the first thing we check, because
	// it is common for pkgsite to not have cached all versions (e.g., pseudo-versions).
	existsAtVersion, err := pkc.KnownAtVersion(ctx, p.Package, ver)
	if err != nil {
		return err
	}
	if existsAtVersion {
		return nil
	}
	return fmt.Errorf("%w: %s at version %s not known to pkgsite", errPackageNotExist, p.Package, ver)
}
