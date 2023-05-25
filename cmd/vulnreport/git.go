// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"

	"golang.org/x/vulndb/internal/derrors"
)

func gitAdd(files ...string) (err error) {
	derrors.Wrap(&err, "git add")
	addArgs := []string{"add"}
	return irun("git", append(addArgs, files...)...)
}

func gitCommit(msg string, files ...string) (err error) {
	derrors.Wrap(&err, "git commit")
	commitArgs := []string{"commit", "-m", msg, "-e"}
	commitArgs = append(commitArgs, files...)
	return irun("git", commitArgs...)
}

func irun(name string, arg ...string) error {
	// Exec git commands rather than using go-git so as to run commit hooks
	// and give the user a chance to edit the commit message.
	cmd := exec.Command(name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
