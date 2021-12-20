// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derrors defines internal error values to categorize the different
// types error semantics supported by x/vuln.
package derrors

import (
	"fmt"

	"cloud.google.com/go/errorreporting"
)

// Wrap adds context to the error and allows
// unwrapping the result to recover the original error.
//
// Example:
//
//	defer derrors.Wrap(&err, "copy(%s, %s)", dst, src)
func Wrap(errp *error, format string, args ...interface{}) {
	if *errp != nil {
		*errp = fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), *errp)
	}
}

// WrapAndReport calls Wrap followed by Report.
func WrapAndReport(errp *error, format string, args ...interface{}) {
	Wrap(errp, format, args...)
	if *errp != nil {
		Report(*errp)
	}
}

var repClient *errorreporting.Client

// SetReportingClient sets an errorreporting client, for use by Report.
func SetReportingClient(c *errorreporting.Client) {
	repClient = c
}

// Report uses the errorreporting API to report an error.
func Report(err error) {
	if repClient != nil {
		repClient.Report(errorreporting.Entry{Error: err})
	}
}
