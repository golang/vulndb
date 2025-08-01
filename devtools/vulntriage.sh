#!/bin/bash

# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# --- Usage ---
# This script automates the common workflow for updating the Go vulnerability database.
# It performs the following steps in sequence:
# 1. Creates a new local git branch (or switches to an existing one).
# 2. Pulls the latest changes from the remote repository.
# 3. Installs the latest version of the 'vulnreport' tool.
# 4. Runs 'vulnreport triage'.
# 5. Runs 'vulnreport create'.
# 6. Runs 'vulnreport commit' for UNREVIEWED and NEEDS_REVIEW statuses.
#
# Options:
#   --batch <size>:  Sets the batch size for commit operations (default: 20).
#   --no-triage:     Skips the 'vulnreport triage' step.
#   --no-create:     Skips the 'vulnreport create' step.
#   --no-commit:     Skips the 'vulnreport commit' steps.
#   --branch <name>: Specifies the git branch name to use
#                    (default: vulnreport-update-YYYY-MM-DD).
#
# Example:
#   ./run_vulnreport.sh
#   ./run_vulnreport.sh --no-triage --batch 10
#   ./run_vulnreport.sh --branch my-feature-branch

BATCH_SIZE=20
TRIAGE=true
CREATE=true
COMMIT=true
COMMIT_STATUSES=("UNREVIEWED" "NEEDS_REVIEW")
BRANCH_NAME="vulnreport-update-$(date +%Y-%m-%d)"

info() {
  echo "[INFO] $1"
}

run_cmd() {
  info "Running: $*"
  "$@"
  local status=$?
  if [ $status -ne 0 ]; then
    echo "[WARN] Command failed with status $status: $*"
  fi
  return $status
}

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --batch) BATCH_SIZE="$2"; shift ;;
    --no-triage) TRIAGE=false ;;
    --no-create) CREATE=false ;;
    --no-commit) COMMIT=false ;;
    --branch) BRANCH_NAME="$2"; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

info "Attempting to create and switch to new branch: $BRANCH_NAME"
if git checkout -b "$BRANCH_NAME"; then
  info "Successfully created and switched to new branch: $BRANCH_NAME"
else
  info "Failed to create new branch. Attempting to switch to existing branch: $BRANCH_NAME"
  git checkout "$BRANCH_NAME" || { echo "[ERROR] Failed to create or switch to branch $BRANCH_NAME. Aborting."; exit 1; }
  info "Successfully switched to existing branch: $BRANCH_NAME"
fi

info "Pulling latest changes..."
git pull origin master --rebase || \
  { echo "[ERROR] Failed to pull latest changes. Aborting."; exit 1; }
info "Successfully synced with remote."

info "Installing vulnreport tool..."
go install ./cmd/vulnreport
if [ $? -ne 0 ]; then
   echo "[ERROR] Failed to install vulnreport. Aborting." >&2
   exit 1
fi

if $TRIAGE; then
  run_cmd vulnreport triage
  if [ $? -ne 0 ]; then
    echo "[ERROR] 'vulnreport triage' failed. Aborting." >&2
    exit 1
  fi
fi

if $CREATE; then
  run_cmd vulnreport create
  if [ $? -ne 0 ]; then
    echo "[ERROR] 'vulnreport create' failed. Aborting." >&2
    exit 1
  fi
fi

if $COMMIT; then
  for status in "${COMMIT_STATUSES[@]}"; do
    run_cmd vulnreport -batch="${BATCH_SIZE}" -status="${status}" commit
  done
fi
