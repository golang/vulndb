// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"time"

	"golang.org/x/vulndb/osv"
)

// Cache interface for vuln DB caching.
type Cache interface {
	ReadIndex(string) (osv.DBIndex, time.Time, error)
	WriteIndex(string, osv.DBIndex, time.Time) error
	ReadEntries(string, string) ([]*osv.Entry, error)
	WriteEntries(string, string, []*osv.Entry) error
}
