// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"net/url"
	"strings"

	"golang.org/x/vulndb/internal/idstr"
	"golang.org/x/vulndb/internal/osv"
)

func isFix(url string) bool {
	return strings.Contains(url, "go-review.googlesource.com") ||
		strings.Contains(url, "/commit/") || strings.Contains(url, "/commits/") ||
		strings.Contains(url, "/pull/") || strings.Contains(url, "/cl/")
}

func isIssue(url string) bool {
	return strings.Contains(url, "/issue/") || strings.Contains(url, "/issues/")
}

// ReferenceFromUrl creates a new Reference from a url
// with Type inferred from the contents of the url.
func ReferenceFromUrl(u string) *Reference {
	unescaped, err := url.PathUnescape(u)
	if err != nil {
		// Ignore error and use original.
		unescaped = u
	}
	typ := osv.ReferenceTypeWeb
	switch {
	case isFix(unescaped):
		typ = osv.ReferenceTypeFix
	case isIssue(unescaped):
		typ = osv.ReferenceTypeReport
	case idstr.IsAdvisory(unescaped):
		typ = osv.ReferenceTypeAdvisory
	}
	return &Reference{
		Type: typ,
		URL:  unescaped,
	}
}
