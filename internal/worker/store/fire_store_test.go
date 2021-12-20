// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17
// +build go1.17

package store

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os/user"
	"testing"
	"time"
)

var project = flag.String("project", "", "GCP project for Firestore")

func TestFireStore(t *testing.T) {
	if *project == "" {
		t.Skip("missing -project")
	}
	ctx := context.Background()
	// Create a client with a unique namespace for this test.
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(1000)
	namespace := fmt.Sprintf("testing-%s-%d", username, r)
	t.Logf("testing in namespace %s", namespace)

	fs, err := NewFireStore(ctx, *project, namespace)
	if err != nil {
		t.Fatal(err)
	}
	// Delete the namespace when we're done.
	defer func() {
		if err := fs.Clear(ctx); err != nil {
			t.Log(err)
		}
	}()

	testStore(t, fs)
}
