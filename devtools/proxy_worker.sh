#!/bin/bash

# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Start the cloud run proxy pointing at a worker.

# To install the proxy:
#   go install github.com/GoogleCloudPlatform/cloud-run-proxy@latest

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

env=$1

cloud-run-proxy -host $(worker_url $env) -token $(impersonation_token $env)
