// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package genericosv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func newTestClient(expectedEndpoint, fakeResponse string) *osvDevClient {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet &&
			r.URL.Path == "/"+expectedEndpoint {
			_, _ = w.Write([]byte(fakeResponse))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}
	s := httptest.NewServer(http.HandlerFunc(handler))
	return &osvDevClient{s.Client(), s.URL}
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	c := newTestClient("ID-123", `{"id":"ID-123"}`)
	got, err := c.Fetch(ctx, "ID-123")
	if err != nil {
		t.Fatal(err)
	}
	want := &Entry{ID: "ID-123"}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("fetch() mismatch (-want, +got):\n%s", diff)
	}
}
