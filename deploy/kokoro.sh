#!/usr/bin/env bash
# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -ex

# Make a full clone of the repo so that gendb can find missing PublishDates in
# reports by reading the commit history.
#
# Kokoro creates a shallow clone. Attempts to
# deepen the clone with `git fetch --unshallow` failed,
# apparently because Kokoro uses the `rpc:` scheme to
# clone the repo.

git clone https://go.googlesource.com/vulndb
cd vulndb

# Copy the existing vuln DB into a local directory so we can diff it.
mkdir old-db
gsutil -q -m cp -r gs://go-vulndb/* old-db

# Generate a copy of the DB using the current state of the repo
# and diff it with the old one. Do all this in a docker container
# so we can select the version of Go that we want.
docker run --rm \
  -v $PWD:/vulndb \
  -w /vulndb \
  golang:1.17.3 \
  /bin/bash -c 'go run ./cmd/gendb -repo /vulndb -out new-db &&
                go run ./cmd/dbdiff old-db new-db'
