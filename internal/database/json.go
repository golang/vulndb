// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package database

import (
	"encoding/json"
	"os"

	"golang.org/x/vulndb/internal/derrors"
)

func WriteJSON(filename string, value any, indent bool) (err error) {
	defer derrors.Wrap(&err, "writeJSON(%s)", filename)

	j, err := jsonMarshal(value, indent)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, j, 0644)
}

func jsonMarshal(v any, indent bool) ([]byte, error) {
	if indent {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}
