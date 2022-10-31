#!/bin/bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

# Deploy database files.
gsutil -m cp -r /workspace/db/* gs://go-vulndb

# Deploy web files.
for file in index 404 copyright privacy; do
    gsutil -h "Content-Type:text/html" cp webconfig/$file.html gs://go-vulndb/$file
done
gsutil cp webconfig/favicon.ico gs://go-vulndb

