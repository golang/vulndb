// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log implements event handlers for logging.
package log

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/exp/event"
	"golang.org/x/exp/event/severity"
)

func WithLineLogger(ctx context.Context) context.Context {
	return event.WithExporter(ctx, event.NewExporter(&lineHandler{w: os.Stderr}, nil))
}

// lineHandler writes log events one per line in an easy-to-read format:
// time level message label1=value1 label2=value2 ...
type lineHandler struct {
	mu sync.Mutex // ensure a log line is not interrupted
	w  io.Writer
}

// Event implements event.Handler.Event for log events.
func (h *lineHandler) Event(ctx context.Context, ev *event.Event) context.Context {
	if ev.Kind != event.LogKind {
		return ctx
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	var msg, level string
	var others []string
	for _, lab := range ev.Labels {
		switch lab.Name {
		case "msg":
			msg = lab.String()
		case "level":
			level = strings.ToUpper(lab.String())
		default:
			others = append(others, fmt.Sprintf("%s=%s", lab.Name, lab.String()))
		}
	}
	var s string
	if len(others) > 0 {
		s = " " + strings.Join(others, " ")
	}
	if level != "" {
		level = " " + level
	}
	fmt.Fprintf(h.w, "%s%s %s%s\n", ev.At.Format("2006/01/02 15:04:05"), level, msg, s)
	return ctx
}

// Debug emits one log event at the Debug severity.
func Debug(ctx context.Context, message string, labels ...event.Label) {
	event.Log(ctx, message, append(labels, severity.Debug.Label())...)
}

// Info emits one log event at the Info severity.
func Info(ctx context.Context, message string, labels ...event.Label) {
	event.Log(ctx, message, append(labels, severity.Info.Label())...)
}

// Warning emits one log event at the Warning severity.
func Warning(ctx context.Context, message string, labels ...event.Label) {
	event.Log(ctx, message, append(labels, severity.Warning.Label())...)
}

// Error emits one log event at the Error severity.
func Error(ctx context.Context, message string, labels ...event.Label) {
	event.Log(ctx, message, append(labels, severity.Error.Label())...)
}

// Debugf logs a formatted message with no labels at the Debug severity.
func Debugf(ctx context.Context, format string, args ...interface{}) {
	Debug(ctx, fmt.Sprintf(format, args...))
}

// Infof logs a formatted message with no labels at the Info severity.
func Infof(ctx context.Context, format string, args ...interface{}) {
	Info(ctx, fmt.Sprintf(format, args...))
}

// Warningf logs a formatted message with no labels at the Warning severity.
func Warningf(ctx context.Context, format string, args ...interface{}) {
	Warning(ctx, fmt.Sprintf(format, args...))
}

// Errorf logs a formatted message with no labels at the Error severity.
func Errorf(ctx context.Context, format string, args ...interface{}) {
	Error(ctx, fmt.Sprintf(format, args...))
}
