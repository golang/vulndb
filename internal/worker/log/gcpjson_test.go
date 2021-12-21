// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"bytes"
	"context"
	"testing"
	"time"

	"golang.org/x/exp/event"
	"golang.org/x/exp/event/severity"
)

func TestGCPJSON(t *testing.T) {
	now := time.Date(2002, 3, 4, 5, 6, 7, 0, time.UTC)
	for _, test := range []struct {
		ev   event.Event
		want string
	}{
		{
			ev: event.Event{
				At:   now,
				Kind: event.LogKind,
				Labels: []event.Label{
					event.String("msg", "hello"),
					event.Int64("count", 17),
					severity.Info.Label(),
				},
			},
			want: `{"time": "2002-03-04T05:06:07Z", "logging.googleapis.com/trace": "tid", "message": "hello", "severity": "info", "logging.googleapis.com/labels": {"count": "17"}}
`,
		},
	} {
		var buf bytes.Buffer
		h := &gcpJSONHandler{w: &buf, traceID: "tid"}
		h.Event(context.Background(), &test.ev)
		got := buf.String()
		if got != test.want {
			t.Errorf("%+v:\ngot  %s\nwant %s", test.ev, got, test.want)
		}
	}
}
