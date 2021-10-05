#!/usr/bin/env bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

prev=$(find reports/GO-* | tail -n 1 | sed -n 's/reports\/GO-[0-9]*-\([0-9]*\).yaml/\1/p')
new=$(printf "%04d" $(expr $prev + 1))
year=$(date +"%Y")
cp template reports/GO-$year-$new.yaml
