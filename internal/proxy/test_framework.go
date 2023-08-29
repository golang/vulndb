// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// NewTestClient creates a new client for testing.
// If update is true, the returned client contacts the real
// proxy and updates the file "testdata/proxy/<TestName>.json" with
// the responses it saw.
// If update is false, the returned client is a fake that
// reads saved responses from "testdata/proxy/<TestName>.json".
func NewTestClient(t *testing.T, update bool) (*Client, error) {
	t.Helper()

	fpath := responsesFile(t)
	if update {
		// Set up a real proxy and register a function to write the responses
		// after the test runs.
		pc := NewClient(http.DefaultClient, ProxyURL)
		t.Cleanup(func() {
			if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				t.Error(err)
				return
			}
			if err := pc.writeResponses(fpath); err != nil {
				t.Error(err)
			}
		})
		return pc, nil
	}

	// Get the fake client from the saved responses.
	b, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	var responses map[string]*response
	err = json.Unmarshal(b, &responses)
	if err != nil {
		return nil, err
	}
	c, cleanup := fakeClient(responses)
	t.Cleanup(cleanup)

	return c, nil
}

// response is a representation of an HTTP response used to
// facilitate testing.
type response struct {
	Body       string `json:"body,omitempty"`
	StatusCode int    `json:"status_code"`
}

// fakeClient creates a client that returns hard-coded responses.
// endpointsToResponses is a map from proxy endpoints
// (with no server url, and no leading '/'), to their desired responses.
func fakeClient(endpointsToResponses map[string]*response) (c *Client, cleanup func()) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		for endpoint, response := range endpointsToResponses {
			if r.Method == http.MethodGet &&
				r.URL.Path == "/"+endpoint {
				if response.StatusCode == http.StatusOK {
					_, _ = w.Write([]byte(response.Body))
				} else {
					w.WriteHeader(response.StatusCode)
				}
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	}
	s := httptest.NewServer(http.HandlerFunc(handler))
	return NewClient(s.Client(), s.URL), func() { s.Close() }
}

func responsesFile(t *testing.T) string {
	return filepath.Join("testdata", "proxy", t.Name()+".json")
}

// responses returns a map from endpoints to the latest response received for each endpoint.
//
// Intended for testing: the output can be passed to NewTestClient to create a fake client
// that returns the same responses.
func (c *Client) responses() map[string]*response {
	m := make(map[string]*response)
	for key, status := range c.errLog.getData() {
		m[key] = &response{StatusCode: status}
	}
	for key, b := range c.cache.getData() {
		m[key] = &response{Body: string(b), StatusCode: http.StatusOK}
	}
	return m
}

func (pc *Client) writeResponses(filepath string) error {
	responses, err := json.MarshalIndent(pc.responses(), "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, responses, 0644)
}

// An in-memory store of the errors seen so far.
// Used by the responses() function, for testing.
type errLog struct {
	data map[string]int
	mu   sync.Mutex
}

func newErrLog() *errLog {
	return &errLog{data: make(map[string]int)}
}

func (e *errLog) set(key string, status int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.data[key] = status
}

func (e *errLog) getData() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.data
}
