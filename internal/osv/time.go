// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package osv

import (
	"encoding/json"
	"time"
)

// Time is a wrapper for time.Time that marshals and unmarshals
// RFC3339 formatted UTC strings.
type Time struct {
	time.Time
}

// MarshalJSON encodes the time as
// an RFC3339-formatted string in UTC (ending in "Z"),
// as required by the OSV specification.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format(time.RFC3339))
}

// UnmarshalJSON decodes an RFC3339-formatted string
// into a Time struct. It errors if data
// is not a valid RFC3339-formatted string.
func (t *Time) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	time, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = time.UTC()
	return nil
}
