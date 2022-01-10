#!/bin/bash

# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Deploy the vuln worker to Cloud Run, using Cloud Build.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

# Report whether the current repo's workspace has no uncommitted files.
clean_workspace() {
  [[ $(git status --porcelain) == '' ]]
}

main() {
  local prefix=
  if [[ $1 = '-n' ]]; then
    prefix='echo dryrun: '
    shift
  fi

  local env=$1

  case $env in
    dev|prod);;
    *)
      die "usage: $0 [-n] (dev | prod)"
  esac

  local project=$(tfvar ${env}_project)
  local commit=$(git rev-parse --short HEAD)
  local unclean
  if ! clean_workspace; then
    unclean="-unclean"
  fi

  $prefix gcloud builds submit \
    --project $project \
    --config deploy/worker.yaml \
    --substitutions SHORT_SHA=${commit}${unclean},_ENV=$env
}

main $@
