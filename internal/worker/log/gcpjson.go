// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/exp/event"
)

// NewGCPJSONLogger returns a handler which logs events in a format that is
// understood by Google Cloud Platform logging.
func NewGCPJSONHandler(w io.Writer, traceID string) event.Handler {
	return &gcpJSONHandler{w: w, traceID: traceID}
}

type gcpJSONHandler struct {
	traceID string
	mu      sync.Mutex // ensure a log line is not interrupted
	w       io.Writer
}

// Event implements event.Handler.Event.
// It handles Log events and ignores all others.
// See https://cloud.google.com/logging/docs/agent/logging/configuration#special-fields
// for treatment of special fields.
func (h *gcpJSONHandler) Event(ctx context.Context, ev *event.Event) context.Context {
	if ev.Kind != event.LogKind {
		return ctx
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	fmt.Fprintf(h.w, `{"time": %q`, ev.At.Format(time.RFC3339))
	if h.traceID != "" {
		fmt.Fprintf(h.w, `, "logging.googleapis.com/trace": %q`, h.traceID)
	}
	gcpLabels := map[string]string{}
	for _, l := range ev.Labels {
		var key string
		switch l.Name {
		case "msg":
			key = "message"
		case "level":
			key = "severity"
		default:
			gcpLabels[l.Name] = l.String() // already quoted, regardless of label kind
			continue
		}
		fmt.Fprintf(h.w, ", %q: ", key)
		switch {
		case !l.HasValue():
			fmt.Fprint(h.w, "null")
		case l.IsInt64():
			fmt.Fprintf(h.w, "%d", l.Int64())
		case l.IsUint64():
			fmt.Fprintf(h.w, "%d", l.Uint64())
		case l.IsFloat64():
			fmt.Fprintf(h.w, "%g", l.Float64())
		case l.IsBool():
			fmt.Fprintf(h.w, "%t", l.Bool())
		default:
			fmt.Fprintf(h.w, "%q", l.String())
		}
	}
	if len(gcpLabels) > 0 {
		fmt.Fprintf(h.w, `, "logging.googleapis.com/labels": {`)
		first := true
		for k, v := range gcpLabels {
			if !first {
				fmt.Fprint(h.w, ", ")
			}
			first = false
			fmt.Fprintf(h.w, "%q: %q", k, v)
		}
		fmt.Fprint(h.w, "}")
	}
	fmt.Fprint(h.w, "}\n")
	return ctx
}
