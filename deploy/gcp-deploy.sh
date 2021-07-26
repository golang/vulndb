#!/bin/bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

deploy=$(
	git cat-file -p 'HEAD' |
	awk '
		BEGIN { flag = "false" }
		/^Reviewed-on:/ { flag = "false" }
		/^Vulndb-Deploy:/ { flag = "true" }
		END {print flag}
	'
)

if $deploy; then
    gsutil -m cp -r /workspace/db/* gs://go-vulndb
fi