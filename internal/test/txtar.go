// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
)

func WriteTxtar(filename string, files []txtar.File, comment string) error {
	if err := os.MkdirAll(filepath.Dir(filename), os.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(filename, txtar.Format(
		&txtar.Archive{
			Comment: []byte(addBoilerplate(currentYear(), comment)),
			Files:   files,
		},
	), 0666); err != nil {
		return err
	}

	return nil
}

// addBoilerplate adds the copyright string for the given year to the
// given comment, and some additional spacing for readability.
func addBoilerplate(year int, comment string) string {
	return fmt.Sprintf(`Copyright %d The Go Authors. All rights reserved.
Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file.

%s

`, year, comment)
}

func currentYear() int {
	year, _, _ := time.Now().Date()
	return year
}

var copyrightRE = regexp.MustCompile(`Copyright (\d+)`)

// findCopyrightYear returns the copyright year in this comment,
// or an error if none is found.
func findCopyrightYear(comment string) (int, error) {
	matches := copyrightRE.FindStringSubmatch(comment)
	if len(matches) != 2 {
		return 0, errors.New("comment does not contain a copyright year")
	}
	year, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, err
	}
	return year, nil
}

// CheckComment checks the validity of a txtar comment.
// It checks that the "got" comment is the same as would be generated
// by WriteTxtar(..., wantComment), but allows any copyright year.
//
// For testing.
func CheckComment(wantComment, got string) error {
	year, err := findCopyrightYear(got)
	if err != nil {
		return err
	}

	want := addBoilerplate(year, wantComment)
	if diff := cmp.Diff(want, got); diff != "" {
		return fmt.Errorf("comment mismatch (-want, +got):\n%s", diff)
	}

	return nil
}

// FindFile returns the first "file" with the given filename in the
// txtar archive, or an error if none is found.
//
// Intended for testing.
func FindFile(ar *txtar.Archive, filename string) (*txtar.File, error) {
	for _, f := range ar.Files {
		if f.Name == filename {
			return &f, nil
		}
	}
	return nil, fmt.Errorf("%s not found", filename)
}

func ReadTxtarFS(filename string) (fs.FS, error) {
	a, err := txtar.ParseFile(filename)
	if err != nil {
		return nil, err
	}
	m := make(fstest.MapFS)
	for _, a := range a.Files {
		m[a.Name] = &fstest.MapFile{Data: a.Data}
	}
	return m, nil
}
