// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package report

import (
	"os"
	"path/filepath"

	"golang.org/x/vulndb/internal/derrors"
)

var (
	// YAMLDir is the name of the directory in the vulndb repo that
	// contains reports.
	YAMLDir = "data/reports"

	// ExcludedDir is the name of the directory in the vulndb repo that
	// contains excluded reports.
	ExcludedDir = "data/excluded"
)

func GetAllExisting() (byIssue map[int]*Report, byFile map[string]*Report, err error) {
	defer derrors.Wrap(&err, "GetAllExisting")

	byIssue = make(map[int]*Report)
	byFile = make(map[string]*Report)
	for _, dir := range []string{YAMLDir, ExcludedDir} {
		f, err := os.Open(dir)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		names, err := f.Readdirnames(0)
		if err != nil {
			return nil, nil, err
		}
		for _, name := range names {
			name := filepath.Join(dir, name)
			_, _, iss, err := ParseFilepath(name)
			if err != nil {
				return nil, nil, err
			}
			r, err := Read(name)
			if err != nil {
				return nil, nil, err
			}
			byIssue[iss] = r
			byFile[name] = r
		}
	}

	return byIssue, byFile, nil
}
