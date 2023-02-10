// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import "strings"

// referenceFromUrl creates a new Reference from a url
// with Type inferred from the contents of the url.
func referenceFromUrl(url string) *Reference {
	typ := ReferenceTypeWeb
	switch {
	case strings.Contains(url, "go-review.googlesource.com"):
		typ = ReferenceTypeFix
	case strings.Contains(url, "commit"):
		typ = ReferenceTypeFix
	case strings.Contains(url, "pull"):
		typ = ReferenceTypeFix
	case strings.Contains(url, "pr"):
		typ = ReferenceTypeFix
	case strings.Contains(url, "/issue/"):
		typ = ReferenceTypeReport
	}
	return &Reference{
		Type: typ,
		URL:  url,
	}
}
