// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package priority

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/csv"
	"strconv"
)

//go:embed data/importers.csv.gz
var importers []byte

func LoadModuleMap() (map[string]int, error) {
	return gzCSVToMap(importers)
}

func gzCSVToMap(b []byte) (map[string]int, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(gzr)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	m := make(map[string]int)
	for _, record := range records[1:] {
		if len(record) != 2 {
			continue
		}
		n, err := strconv.Atoi(record[1])
		if err != nil {
			continue
		}
		m[record[0]] = n
	}

	return m, nil
}
