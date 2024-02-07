// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"fmt"
	"io"
	"os"

	"log"

	"golang.org/x/vulndb/cmd/vulnreport/color"
)

func SetQuiet() {
	loggers[infoLvl] = log.New(io.Discard, "", 0)
}

func RemoveColor() {
	for lvl := range loggers {
		loggers[lvl].SetPrefix(metas[lvl].prefix)
	}
	colorize = false
}

const (
	infoLvl int = iota
	outLvl
	warnLvl
	errLvl
)

func defaultLoggers() []*log.Logger {
	ls := make([]*log.Logger, len(metas))
	for lvl, lm := range metas {
		ls[lvl] = log.New(lm.w, lm.color+lm.prefix, 0)
	}
	return ls
}

var (
	loggers = defaultLoggers()

	// Whether to display colors in logs.
	colorize bool = true

	metas = []*metadata{
		infoLvl: {
			prefix: "info: ",
			color:  color.Faint,
			w:      os.Stderr,
		},
		outLvl: {
			prefix: "",
			color:  color.Reset,
			w:      os.Stdout,
		},
		warnLvl: {
			prefix: "WARNING: ",
			color:  color.YellowHi,
			w:      os.Stderr,
		},
		errLvl: {
			prefix: "ERROR: ",
			color:  color.RedHi,
			w:      os.Stderr,
		},
	}
)

type metadata struct {
	prefix string
	color  string
	w      io.Writer
}

func printf(lvl int, format string, v ...any) {
	println(lvl, fmt.Sprintf(format, v...))
}

func println(lvl int, v ...any) {
	l := loggers[lvl]
	l.Println(v...)
	if colorize {
		fmt.Fprint(l.Writer(), color.Reset)
	}
}

func Infof(format string, v ...any) {
	printf(infoLvl, format, v...)
}

func Outf(format string, v ...any) {
	printf(outLvl, format, v...)
}

func Warnf(format string, v ...any) {
	printf(warnLvl, format, v...)
}

func Errf(format string, v ...any) {
	printf(errLvl, format, v...)
}

func Info(v ...any) {
	println(infoLvl, v...)
}

func Out(v ...any) {
	println(outLvl, v...)
}

func Warn(v ...any) {
	println(warnLvl, v...)
}

func Err(v ...any) {
	println(errLvl, v...)
}
