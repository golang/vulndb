// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log implements event handlers for logging.
package log

import (
	"context"
	"fmt"
	"golang.org/x/exp/slog"
	"io"
	"os"
	"time"
)

type Attrs []slog.Attr

func With(args ...any) Attrs {
	var r slog.Record
	r.Add(args...)
	var as Attrs
	r.Attrs(func(a slog.Attr) bool {
		as = append(as, a)
		return true
	})
	return as
}

func (as Attrs) Debugf(ctx context.Context, format string, args ...interface{}) {
	as.logf(ctx, slog.LevelDebug, format, args...)
}

func (as Attrs) Infof(ctx context.Context, format string, args ...interface{}) {
	as.logf(ctx, slog.LevelInfo, format, args...)
}

func (as Attrs) Warningf(ctx context.Context, format string, args ...interface{}) {
	as.logf(ctx, slog.LevelWarn, format, args...)
}

func (as Attrs) Errorf(ctx context.Context, format string, args ...interface{}) {
	as.logf(ctx, slog.LevelError, format, args...)
}

func Debugf(ctx context.Context, format string, args ...interface{}) {
	Attrs{}.logf(ctx, slog.LevelDebug, format, args...)
}

func Infof(ctx context.Context, format string, args ...interface{}) {
	Attrs{}.logf(ctx, slog.LevelInfo, format, args...)
}

func Warningf(ctx context.Context, format string, args ...interface{}) {
	Attrs{}.logf(ctx, slog.LevelWarn, format, args...)
}

func Errorf(ctx context.Context, format string, args ...interface{}) {
	Attrs{}.logf(ctx, slog.LevelError, format, args...)
}

func (as Attrs) logf(ctx context.Context, level slog.Level, format string, args ...interface{}) {
	FromContext(ctx).LogAttrs(ctx, level, fmt.Sprintf(format, args...), as...)
}

type key struct{}

func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(key{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

func NewContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, key{}, l)
}

// NewGoogleCloudHandler returns a Handler that outputs JSON for the Google
// Cloud logging service.
// See https://cloud.google.com/logging/docs/agent/logging/configuration#special-fields
// for treatment of special fields.
func NewGoogleCloudHandler(level slog.Leveler) slog.Handler {
	return newGoogleCloudHandler(level, os.Stderr)
}

func newGoogleCloudHandler(level slog.Leveler, w io.Writer) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: gcpReplaceAttr,
	})
}

func gcpReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case "time":
		if a.Value.Kind() == slog.KindTime {
			a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
		}
	case "msg":
		a.Key = "message"
	case "level":
		a.Key = "severity"
	case "traceID":
		a.Key = "logging.googleapis.com/trace"
	}
	return a
}
