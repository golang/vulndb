// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ghsa

import (
	"context"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var githubTokenFile = flag.String("ghtokenfile", "",
	"path to file containing GitHub access token")

func TestList(t *testing.T) {
	if *githubTokenFile == "" {
		t.Skip("-ghtokenfile not provided")
	}
	bytes, err := os.ReadFile(*githubTokenFile)
	if err != nil {
		t.Fatal(err)
	}
	accessToken := strings.TrimSpace(string(bytes))
	// There were three relevant SAs From Jan 1 to Feb 7 2022.
	got, err := List(context.Background(), accessToken, time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	want := 3
	if len(got) < want {
		t.Errorf("got %d, want at least %d", len(got), want)
	}
}
