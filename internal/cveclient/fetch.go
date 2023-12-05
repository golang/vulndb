// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cveclient

import "golang.org/x/vulndb/internal/cveschema5"

// Fetch returns the CVE record associated with the ID.
// It is intended one-off (non-batch) requests, and
// is much faster than cvelistrepo.FetchCVE.
func Fetch(id string) (*cveschema5.CVERecord, error) {
	c := New(Config{
		Endpoint: ProdEndpoint,
	})
	return c.RetrieveRecord(id)
}
