// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/exp/slog"
	"testing"
	"time"
)

// TODO(jba): is it important to put additional attrs under "logging.googleapis.com/labels"?

func TestGoogleCloudHandler(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newGoogleCloudHandler(slog.LevelInfo, &buf))
	l = l.With("logging.googleapis.com/trace", "tid")
	now := time.Now()
	l.Info("hello", slog.String("foo", "bar"), slog.Int("count", 17))
	got := buf.String()
	want := fmt.Sprintf(`{"time":%q,"severity":"INFO","message":"hello","logging.googleapis.com/trace":"tid","foo":"bar","count":17}
`, now.Format(time.RFC3339))
	if got != want {
		t.Errorf("\ngot  %s\nwant %s", got, want)
	}

	buf.Reset()
	ctx := NewContext(context.Background(), l)
	now = time.Now()
	With("a", "b").Warningf(ctx, "hi")
	got = buf.String()
	want = fmt.Sprintf(`{"time":%q,"severity":"WARN","message":"hi","logging.googleapis.com/trace":"tid","a":"b"}
`, now.Format(time.RFC3339))
	if got != want {
		t.Errorf("\ngot  %s\nwant %s", got, want)
	}

}
