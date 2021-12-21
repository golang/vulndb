#!/bin/bash

# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Visit a URL on the vuln worker.

set -e

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

env=$1
path=$2

case $env in
  dev)
    svc_acct=impersonate-for-iap@go-discovery-exp.iam.gserviceaccount.com
    url=https://dev-vuln-worker-ku6ias4ydq-uc.a.run.app
    ;;
  prod)
    svc_acct=impersonate-for-iap@go-discovery.iam.gserviceaccount.com
    url=https://prod-vuln-worker-cf7lo3kiaq-uc.a.run.app
    ;;
  *) die "usage: $0 (dev | prod)"
esac
oauth_client_id=$(tfvar ${env}_client_id)

if [[ $oauth_client_id = '' ]]; then
  die "${env}_client_id is missing from your terraform.tfvars file"
fi

tok=$(gcloud --impersonate-service-account $svc_acct auth print-identity-token --audiences $oauth_client_id --include-email)

if [[ $path = update* || $path = issue* ]]; then
  args="-X POST"
fi

curl $args -i -H "Authorization: Bearer $tok" $url/$path
