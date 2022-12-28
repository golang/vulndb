// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package githubtest provides a test client and server for testing the GitHub API
// client.
package githubtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/vulndb/internal/issues"
)

const (
	TestOwner = "test-owner"
	TestRepo  = "test-repo"
	TestToken = "test-token"

	testBaseURLPath = "/api-test"
)

// Setup sets up a test HTTP server along with a issues.Client that is
// configured to talk to that test server.
func Setup(ctx context.Context, t *testing.T, cfg *issues.Config) (*issues.Client, *http.ServeMux) {
	mux := http.NewServeMux()
	apiHandler := http.NewServeMux()

	apiHandler.Handle(testBaseURLPath+"/", http.StripPrefix(testBaseURLPath, mux))
	server := httptest.NewServer(apiHandler)

	url, _ := url.Parse(server.URL + testBaseURLPath + "/")
	client := issues.NewTestClient(ctx, cfg, url)
	t.Cleanup(server.Close)
	return client, mux
}
