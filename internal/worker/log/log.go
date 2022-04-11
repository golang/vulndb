// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log implements event handlers for logging.
package log

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/event"
	"golang.org/x/exp/event/severity"
)

// NewLineHandler returns an event Handler that writes log events one per line
// in an easy-to-read format:
//
//	time level message label1=value1 label2=value2 ...
func NewLineHandler(w io.Writer) event.Handler {
	return &lineHandler{w: w}
}

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

type Labels []event.Label

func With(kvs ...interface{}) Labels {
	return Labels(nil).With(kvs...)
}

func (ls Labels) With(kvs ...interface{}) Labels {
	if len(kvs)%2 != 0 {
		panic("args must be key-value pairs")
	}
	for i := 0; i < len(kvs); i += 2 {
		ls = append(ls, pairToLabel(kvs[i].(string), kvs[i+1]))
	}
	return ls
}

func pairToLabel(name string, value interface{}) event.Label {
	if d, ok := value.(time.Duration); ok {
		return event.Duration(name, d)
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		return event.String(name, v.String())
	case reflect.Bool:
		return event.Bool(name, v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return event.Int64(name, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return event.Uint64(name, v.Uint())
	case reflect.Float32, reflect.Float64:
		return event.Float64(name, v.Float())
	default:
		return event.Value(name, value)
	}
}

func (l Labels) logf(ctx context.Context, s severity.Level, format string, args ...interface{}) {
	event.Log(ctx, fmt.Sprintf(format, args...), append(l, s.Label())...)
}

func (l Labels) Debugf(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Debug, format, args...)
}

func (l Labels) Infof(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Info, format, args...)
}

func (l Labels) Warningf(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Warning, format, args...)
}

func (l Labels) Errorf(ctx context.Context, format string, args ...interface{}) {
	l.logf(ctx, severity.Error, format, args...)
}

func Debugf(ctx context.Context, format string, args ...interface{}) {
	Labels(nil).logf(ctx, severity.Debug, format, args...)
}

func Infof(ctx context.Context, format string, args ...interface{}) {
	Labels(nil).logf(ctx, severity.Info, format, args...)
}

func Warningf(ctx context.Context, format string, args ...interface{}) {
	Labels(nil).logf(ctx, severity.Warning, format, args...)
}

func Errorf(ctx context.Context, format string, args ...interface{}) {
	Labels(nil).logf(ctx, severity.Error, format, args...)
}
