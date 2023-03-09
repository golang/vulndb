#!/bin/bash
# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

# Deploy legacy database files.
gsutil -q -m cp -r /workspace/legacydb/* gs://go-vulndb

# Deploy v1 database files.
# The "no-cache" directive indicates that browsers may cache
# the data but must first check that is is fresh by contacting the
# origin server.
gsutil -m -h "Cache-Control:no-cache" cp -r /workspace/db/* gs://go-vulndb

# Set metadata for all .gz files.
# The "no-transform" directive instructs the server
# to always send the data in its original form (i.e., compressed).
gsutil -m setmeta -h "Cache-Control:no-cache, no-transform" \
    -h "Content-Type:application/json" \
    -h "Content-Encoding:gzip" \
     -r gs://go-vulndb/*/*.gz

# Deploy web files.
# index.html is deployed as-is to avoid a name conflict with
# the "index/" folder, but other HTML files are deployed without the
# ".html" suffix for a cleaner URL.
gsutil cp webconfig/index.html gs://go-vulndb
for file in 404 copyright privacy; do
    gsutil -h "Content-Type:text/html" cp webconfig/$file.html gs://go-vulndb/$file
done
gsutil cp webconfig/favicon.ico gs://go-vulndb

