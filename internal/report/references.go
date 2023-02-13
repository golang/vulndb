// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import "strings"

func isFix(url string) bool {
	return strings.Contains(url, "go-review.googlesource.com") ||
		strings.Contains(url, "/commit/") || strings.Contains(url, "/commits/") ||
		strings.Contains(url, "/pull/") || strings.Contains(url, "/cl/")
}

func isIssue(url string) bool {
	return strings.Contains(url, "/issue/") || strings.Contains(url, "/issues/")
}

func isAdvisory(url string) bool {
	return strings.Contains(url, "/advisories/")
}

// referenceFromUrl creates a new Reference from a url
// with Type inferred from the contents of the url.
func referenceFromUrl(url string) *Reference {
	typ := ReferenceTypeWeb
	switch {
	case isFix(url):
		typ = ReferenceTypeFix
	case isIssue(url):
		typ = ReferenceTypeReport
	case isAdvisory(url):
		typ = ReferenceTypeAdvisory
	}
	return &Reference{
		Type: typ,
		URL:  url,
	}
}
