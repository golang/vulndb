// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"context"
	"flag"
	"os"
	"testing"

	"golang.org/x/exp/event"
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vulndb/internal/worker/log"
)

// TestScanModules is slow, so put it behind a flag.
var runScanModulesTest = flag.Bool("scan", false, "run the ScanModules test")

func TestScanModules(t *testing.T) {
	if !*runScanModulesTest {
		t.Skip("-scan flag missing")
	}
	// Verify only that scanRepos works (doesn't return an error).
	ctx := event.WithExporter(context.Background(),
		event.NewExporter(log.NewLineHandler(os.Stderr), nil))
	if err := scanModules(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestScanModule(t *testing.T) {
	ctx := event.WithExporter(context.Background(),
		event.NewExporter(log.NewLineHandler(os.Stderr), nil))
	dbClient, err := vulnc.NewClient([]string{vulnDBURL}, vulnc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := scanModule(ctx, "golang.org/x/mod", "v0.5.1", dbClient)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(got.Vulns), 0; got != want {
		t.Errorf("got %d vulns, want %d", got, want)
	}
}
