#!/bin/bash

# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Script to run the common vulnreport commands in succession.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

go install ./cmd/vulnreport
vulnreport triage
vulnreport create
vulnreport -batch=20 -status=UNREVIEWED commit
vulnreport -batch=20 -status=NEEDS_REVIEW commit