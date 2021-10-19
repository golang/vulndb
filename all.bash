#!/usr/bin/env bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

EXIT_CODE=0

# runcud prints an info log describing the command that is about to be run, and
# then runs it. It sets EXIT_CODE to non-zero if the command fails, but does not exit
# the script.
runcmd() {
  # Truncate command logging for narrow terminals.
  # Account for the 2 characters of '$ '.
  maxwidth=$(( $(tput cols) - 2 ))
  if [[ ${#msg} -gt $maxwidth ]]; then
    msg="${msg::$(( maxwidth - 3 ))}..."
  fi

  echo -e "$@\n" 1>&2;
  $@ || err "command failed"
}

# ensure_go_binary verifies that a binary exists in $PATH corresponding to the
# given go-gettable URI. If no such binary exists, it is fetched via `go get`.
ensure_go_binary() {
  local binary=$(basename $1)
  if ! [ -x "$(command -v $binary)" ]; then
    info "Installing: $1"
    # Run in a subshell for convenience, so that we don't have to worry about
    # our PWD.
    (set -x; cd && env GO111MODULE=on go get -u $1)
  fi
}

# check_unparam runs unparam on source files.
check_unparam() {
  ensure_go_binary mvdan.cc/unparam
  runcmd unparam ./...
}

# check_vet runs go vet on source files.
check_vet() {
  runcmd go vet -all ./...
}

# check_staticcheck runs staticcheck on source files.
check_staticcheck() {
  ensure_go_binary honnef.co/go/tools/cmd/staticcheck
  runcmd staticcheck $(go list ./... | grep -v third_party | grep -v internal/doc | grep -v internal/render)
}

# check_misspell runs misspell on source files.
check_misspell() {
  ensure_go_binary github.com/client9/misspell/cmd/misspell
  runcmd misspell cmd/**/*.{go,sh} internal/**/* README.md
}

go_linters() {
  check_vet
  check_staticcheck
  check_misspell
  check_unparam
}

go_modtidy() {
  runcmd go mod tidy
}

go_test() {
  runcmd go test ./...
}

usage() {
  cat <<EOUSAGE
Usage: $0 [subcommand]
Available subcommands:
  (empty)        - run all standard checks and tests:
     * headers: check source files for the license disclaimer
     * misspell: run misspell on source files
     * staticcheck: run staticcheck on source files
     * unparam: run unparam on source files
     * vet: run go vet on source files
  help           - display this help message
EOUSAGE
}

main() {
  case "$1" in
    "-h" | "--help" | "help")
      usage
      exit 0
      ;;
    "")
      go_linters
      go_modtidy
      go_test
      ;;
    *)
      usage
      exit 1
  esac
  if [[ $EXIT_CODE != 0 ]]; then
    err "FAILED; see errors above"
  fi
  exit $EXIT_CODE
}

main $@
