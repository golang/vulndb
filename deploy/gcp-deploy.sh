#!/bin/bash
# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

# Deploy v1 database files.
gcloud storage cp --recursive /workspace/db/* gs://go-vulndb

# Deploy web files.
# index.html is deployed as-is to avoid a name conflict with
# the "index/" folder, but other HTML files are deployed without the
# ".html" suffix for a cleaner URL.
gcloud storage cp webconfig/index.html gs://go-vulndb
for file in 404 copyright privacy; do
    gcloud storage cp webconfig/$file.html gs://go-vulndb/$file --content-type="text/html"
done
gcloud storage cp webconfig/favicon.ico gs://go-vulndb
