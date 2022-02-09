#!/usr/bin/env bash
# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

mkdir old-db
gsutil -m cp -r gs://go-vulndb/* old-db

docker run --rm \
  -v $PWD:/vulndb \
  -w /vulndb \
  golang:1.17.3 \
  /bin/bash -c 'go run ./cmd/gendb -repo /vulndb -out new-db &&
                go run ./cmd/dbdiff old-db new-db'
