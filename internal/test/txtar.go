// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/tools/txtar"
)

func WriteTxtar(filename string, files []txtar.File, comment string) error {
	if err := os.MkdirAll(filepath.Dir(filename), os.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(filename, txtar.Format(
		&txtar.Archive{
			Comment: []byte(addCopyright(comment)),
			Files:   files,
		},
	), 0666); err != nil {
		return err
	}

	return nil
}

func addCopyright(comment string) string {
	return fmt.Sprintf("%s\n\n%s\n\n", copyright, comment)
}

var copyright = fmt.Sprintf(`Copyright %d The Go Authors. All rights reserved.
Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file.`, currentYear())

func currentYear() int {
	year, _, _ := time.Now().Date()
	return year
}
