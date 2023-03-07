#!/bin/bash
# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

# Deploy legacy database files.
gsutil -q -m cp -r /workspace/legacydb/* gs://go-vulndb

# Deploy v1 database files.
# The "-z json" flag indicates that all JSON files will be compressed in
# storage on the server, and sent compressed to clients that set the
# "Accept-Encoding:gzip" header.
# (Clients that do not set this header will receive the data uncompressed,
# because the "no-transform" directive is removed in the step below).
gsutil -m cp -z json -r /workspace/db/* gs://go-vulndb

# Set metadata for all files.
# The "no-cache" directive indicates that browsers may cache
# the data but must first check that is is fresh by contacting the
# origin server.
# This step also removes the "no-transform" directive set automatically
# by the "-z" flag above. (The "no-transform" directive instructs the server
# to always compress the data, regardless of the Accept-Encoding header. We
# don't want this behavior.)
gsutil -m setmeta -h "Cache-Control:no-cache" -r gs://go-vulndb

# Deploy web files.
# index.html is deployed as-is to avoid a name conflict with
# the "index/" folder, but other HTML files are deployed without the
# ".html" suffix for a cleaner URL.
gsutil cp webconfig/index.html gs://go-vulndb
for file in 404 copyright privacy; do
    gsutil -h "Content-Type:text/html" cp webconfig/$file.html gs://go-vulndb/$file
done
gsutil cp webconfig/favicon.ico gs://go-vulndb

