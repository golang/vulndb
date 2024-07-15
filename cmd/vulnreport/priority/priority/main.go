// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command priority gives direct access to the module prioritization
// code used by vulnreport triage.
// Prints the priority result for the given module(s).
// Can be used for experimentation / debugging.
// Usage: $ go run ./cmd/vulnreport/priority/priority <module_path>
package main

import (
	"context"
	"log"
	"os"

	vlog "golang.org/x/vulndb/cmd/vulnreport/log"
	"golang.org/x/vulndb/cmd/vulnreport/priority"
	"golang.org/x/vulndb/internal/report"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		log.Fatal("missing module paths")
	}

	ctx := context.Background()

	ms, err := priority.LoadModuleMap()
	if err != nil {
		log.Fatal(err)
	}

	rc, err := report.NewDefaultClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, arg := range args {
		pr, notGo := priority.Analyze(arg, rc.ReportsByModule(arg), ms)
		vlog.Outf("%s:\npriority = %s\n%s", arg, pr.Priority, pr.Reason)
		if notGo != nil {
			vlog.Outf("%s is likely not Go because %s", arg, notGo.Reason)
		}
	}
}
