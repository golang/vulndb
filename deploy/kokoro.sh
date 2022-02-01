#!/usr/bin/env bash
# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e

mkdir old-db
gsutil -m cp -r gs://go-vulndb/* old-db

go install golang.org/x/vulndb/cmd/gendb@latest
go install golang.org/x/vulndb/cmd/dbdiff@latest

export PATH=$PATH:$GOPATH/bin

gendb -reports reports -out new-db
dbdiff old-db new-db
