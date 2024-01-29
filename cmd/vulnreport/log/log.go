// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"io"
	"os"

	"log"
)

var (
	infolog *log.Logger
	outlog  *log.Logger
	warnlog *log.Logger
	errlog  *log.Logger
)

func Init(quiet bool) {
	if quiet {
		infolog = log.New(io.Discard, "", 0)
	} else {
		infolog = log.New(os.Stderr, "info: ", 0)
	}
	outlog = log.New(os.Stdout, "", 0)
	warnlog = log.New(os.Stderr, "WARNING: ", 0)
	errlog = log.New(os.Stderr, "ERROR: ", 0)
}

func Infof(format string, v ...any) {
	infolog.Printf(format, v...)
}

func Outf(format string, v ...any) {
	outlog.Printf(format, v...)
}

func Warnf(format string, v ...any) {
	warnlog.Printf(format, v...)
}

func Errf(format string, v ...any) {
	errlog.Printf(format, v...)
}

func Info(v ...any) {
	infolog.Println(v...)
}

func Out(v ...any) {
	outlog.Println(v...)
}

func Warn(v ...any) {
	warnlog.Println(v...)
}

func Err(v ...any) {
	errlog.Println(v...)
}
