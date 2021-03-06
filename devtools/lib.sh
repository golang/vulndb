# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Library of useful bash functions and variables.

RED=; GREEN=; YELLOW=; NORMAL=;
MAXWIDTH=0

if tput setaf 1 >& /dev/null; then
  RED=`tput setaf 1`
  GREEN=`tput setaf 2`
  YELLOW=`tput setaf 3`
  NORMAL=`tput sgr0`
  MAXWIDTH=$(( $(tput cols) - 2 ))
fi

EXIT_CODE=0

info() { echo -e "${GREEN}$@${NORMAL}" 1>&2; }
warn() { echo -e "${YELLOW}$@${NORMAL}" 1>&2; }
err() { echo -e "${RED}$@${NORMAL}" 1>&2; EXIT_CODE=1; }

die() {
  err $@
  exit 1
}

dryrun=false

# runcmd prints an info log describing the command that is about to be run, and
# then runs it. It sets EXIT_CODE to non-zero if the command fails, but does not exit
# the script.
runcmd() {
  msg="$@"
  if $dryrun; then
    echo -e "${YELLOW}dryrun${GREEN}\$ $msg${NORMAL}"
    return 0
  fi
  # Truncate command logging for narrow terminals.
  # Account for the 2 characters of '$ '.
  if [[ $MAXWIDTH -gt 0 && ${#msg} -gt $MAXWIDTH ]]; then
    msg="${msg::$(( MAXWIDTH - 3 ))}..."
  fi

  echo -e "$@\n" 1>&2;
  $@ || err "command failed"
}

# tfvar NAME returns the value of NAME in the terraform.tfvars file.
tfvar() {
  local name=$1
  awk '$1 == "'$name'" { print substr($3, 2, length($3)-2) }' terraform/terraform.tfvars
}

worker_url() {
  local env=$1
  case $env in
    dev) echo https://dev-vuln-worker-ku6ias4ydq-uc.a.run.app;;
    prod) echo https://prod-vuln-worker-cf7lo3kiaq-uc.a.run.app;;
    *) die "usage: $0 (dev | prod)";;
  esac
}

impersonation_service_account() {
  local env=$1
  case $env in
    dev) echo impersonate-for-iap@go-discovery-exp.iam.gserviceaccount.com;;
    prod) echo impersonate@go-vuln.iam.gserviceaccount.com;;
    *) die "usage: $0 (dev | prod)";;
  esac
}

impersonation_token() {
  local env=$1
  local oauth_client_id=$(tfvar ${env}_client_id)

  if [[ $oauth_client_id = '' ]]; then
    die "${env}_client_id is missing from your terraform.tfvars file"
  fi
  gcloud --impersonate-service-account $(impersonation_service_account $env) \
    auth print-identity-token \
    --audiences $oauth_client_id \
    --include-email
}
