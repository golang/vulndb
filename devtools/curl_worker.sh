#!/bin/bash

# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Visit a URL on the vuln worker.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

env=$1
path=$2

url=$(worker_url $env)
tok=$(impersonation_token $env)

if [[ $path = update* || $path = issue* ]]; then
  args="-X POST"
fi

curl $args -i -H "Authorization: Bearer $tok" $url/$path
