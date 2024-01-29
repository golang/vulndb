// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"golang.org/x/vulndb/internal/derrors"
	"golang.org/x/vulndb/internal/proxy"
	"golang.org/x/vulndb/internal/report"
)

func lint(_ context.Context, filename string, pc *proxy.Client) (err error) {
	defer derrors.Wrap(&err, "lint(%q)", filename)
	infolog.Printf("lint %s\n", filename)

	_, err = report.ReadAndLint(filename, pc)
	return err
}
