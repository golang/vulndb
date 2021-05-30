#!/bin/bash
tmp_dir=$(mktemp -d -t vulndb-XXXX)
go run ./cmd/gendb -reports reports -out $tmp_dir
cd $tmp_dir
gsutil -m cp -r . gs://go-vulndb
cd -
rm -rf $tmp_dir
