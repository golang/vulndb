#!/usr/bin/env bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This file will be run by `go test`.
# See all_test.go in this directory.

go version

# Ensure that installed go binaries are on the path.
# This bash expression follows the algorithm described at the top of
# `go install help`: first try $GOBIN, then $GOPATH/bin, then $HOME/go/bin.
go_install_dir=${GOBIN:-${GOPATH:-$HOME/go}/bin}
PATH=$PATH:$go_install_dir

source devtools/lib.sh

# ensure_go_binary verifies that a binary exists in $PATH corresponding to the
# given go-gettable URI. If no such binary exists, it is fetched via `go get`.
ensure_go_binary() {
  local binary=$(basename $1)
  if ! [ -x "$(command -v $binary)" ]; then
    info "Installing: $1"
    # Install the binary in a way that doesn't affect our go.mod file.
    go install $1
  fi
}

# verify_header checks that all given files contain the standard header for Go
# projects.
verify_header() {
  if [[ "$@" != "" ]]; then
    for FILE in $@
    do
        line="$(head -4 $FILE)"
        if [[ ! $line == *"The Go Authors. All rights reserved."* ]] &&
         [[ ! $line == "// DO NOT EDIT. This file was copied from" ]]; then
              err "missing license header: $FILE"
        fi
    done
  fi
}

# Support ** in globs for finding files throughout the tree.
shopt -s globstar

# check_headers checks that all source files that have been staged in this
# commit, and all other non-third-party files in the repo, have a license
# header.
check_headers() {
  if [[ $# -gt 0 ]]; then
    info "Checking listed files for license header"
    verify_header $*
  else
    # Check code files that have been modified or added.
    info "Checking go and sh files for license header"
    verify_header $(find **/*.go -type f) $(find **/*.sh -type f)
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
  if [[ $(go version) = *go1.17* ]]; then
    ensure_go_binary honnef.co/go/tools/cmd/staticcheck
    runcmd staticcheck ./...
  fi
}

# check_misspell runs misspell on source files.
check_misspell() {
  ensure_go_binary github.com/client9/misspell/cmd/misspell
  # exceptions:
  # "github.com/unknwon/cae" - OK
  # "github.com/julz/importas" - OK
  # Ignore testdata files and the spelling.go file (which contains a list of replacements)
  runcmd find . -type f | grep -v -e "spelling.go" -e "/testdata" | xargs misspell -i "unknwon,importas" -error
}

check_data_osv() {
  commit=$(git log --name-status HEAD^..HEAD)
  if [[ "$commit" =~ .*"D"."data/osv/".* ]]; then
    err "Files in the data/osv/ directory should never be deleted. Use the withdrawn field instead to remove reports. See doc/format.md for details."
  fi
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

runchecks() {
  check_data_osv
  check_headers
  go_linters
  go_modtidy
}

# checkoffline runs all checks that can be performed without network access.
checkoffline() {
  check_data_osv
  check_headers
  check_vet
}

usage() {
  cat <<EOUSAGE
Usage: $0 [subcommand]
Available subcommands:
  help           - display this help message
  offline        - run checks that do not require network access
EOUSAGE
}

main() {
  case "$1" in
    "-h" | "--help" | "help")
      usage
      exit 0
      ;;
    "--offline" | "offline")
      checkoffline
      ;;
    "")
      runchecks
      ;;
    *)
      usage
      exit 1
  esac
  if [[ $EXIT_CODE != 0 ]]; then
    err "checks.bash FAILED; see errors above"
  fi
  exit $EXIT_CODE
}

main $@
