#!/bin/bash

# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Deploy the vuln worker to Cloud Run.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

# Report whether the current repo's workspace has no uncommitted files.
clean_workspace() {
  [[ $(git status --porcelain) == '' ]]
}

docker_image_tag() {
  local timestamp=$(date +%Y%m%dt%H%M%S)
  local commit=$(git rev-parse --short HEAD)
  local unclean
  if ! clean_workspace; then
    unclean="-unclean"
  fi
  echo ${timestamp}-${commit}${unclean}
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
  local image=gcr.io/$project/vuln-worker:$(docker_image_tag)

  $prefix docker build -t $image --build-arg DOCKER_IMAGE=$image -f cmd/worker/Dockerfile .
  $prefix docker push $image
  $prefix gcloud run deploy --quiet --project $project $env-vuln-worker --image $image
  # If there was a rollback, `gcloud run deploy` will create a revision but
  # not point traffic to it. The following command ensures that the new revision
  # will get traffic.
  latestTraffic=$(gcloud run services --project $project describe $env-vuln-worker \
                  --format='value(status.traffic.latestRevision)')
  if [[ $latestTraffic != True ]]; then
    $prefix gcloud run services --project $project update-traffic $env-vuln-worker --to-latest
  fi
}

main $@
