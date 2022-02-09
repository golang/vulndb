# Vulnerability Report Format

The Go vulnerability report format is used to generate JSON files served the
the vulnerability database.

This file format is meant for internal use only, and is subject to change
without warning. See [golang.org/x/vuln](https://golang.org/x/vuln) for
information on the Go Vulnerability database API.

This document explains data within the internal YAML file format.

## Module

**required:** `module` contains the module path of the vulnerable module.

## Package

**required:** `package` contains the import path of the vulnerable module.

## Description

**required:** `description` contains a textual description of the vulnerability
and its impact.

## CVEs

`cves` contains all of the CVE numbers for the vulnerability that
this report pertains to.

## Credit

`credit` contains credit for the person/organization that
discovered/reported the vulnerability.

## Symbols

`symbols` contains an array of vulnerable symbols. If included, only programs
which use these symbols will be marked as vulnerable. If omitted, any program
which imports this module will be marked vulnerable.

These should be the symbols initially detected or identified in the CVE or
other source.

## Derived Symbols

`derived_symbols` are additional symbols that are calculated from `symbols`,
such as by static analysis tools like `govulncheck`.

Potentially, the set of derived symbols can differ with the module version. We
don't attempt to capture that level of detail. Most of the values of
`derived_symbols` as of this writing were obtained from a module version
that was just prior to the version that the report listed as fixed.

## Versions

The `versions` sections of the YAML contain information about when
the vulnerability was introduced, and when it was fixed. If the vulnerability
is fixed in multiple major versions, then the YAML should contain multiple
`versions` sections. If omitted, it is assumed that _every_ version of the
module is vulnerable.

### Introduced

`introduced` contains the version at which the vulnerability was
introduced. If this field is omitted it is assumed that every version, from the
initial commit, up to the `fixed` version is vulnerable.

### Fixed

`fixed` contains the version at which the vulnerability was fixed.
If this field is omitted it is assumed that every version since the
`introduced` version is vulnerable.

## Additional Packages

The `additional_packages` sections of the YAML contain information about
additional packages impacted by the vulnerability. These may be other
submodules which independently implement the same vulnerability, or alternate
module names for the same module.

### Package

`package` contains the import path of the additionally vulnerable
module.

### Symbols

`symbols` contains an array of vulnerable symbols. If included
only programs which use these symbols will be marked as vulnerable. If omitted
any program which imports this module will be marked vulnerable.

### Versions

The `additional_packages.versions` sections contain version ranges for each
additional package, following the same semantics as the `versions` section.

## Links

The `links` section of the YAML contains further information about the
vulnerability.

### Commit

`commit` contains a link to the commit which fixes the
vulnerability.

### PR

`pr` contains a link to the PR/CL which fixes the vulnerability.

### Context

`context` contains an array of additional links which provide
additional context about the vulnerability, i.e. GitHub issues, vulnerability
reports, etc.

## Example

```
module: github.com/example/module
package: github.com/example/module
description: |
  A description of the vulnerability present in this module.

  The description can contain newlines, and a limited set of markup.
cves:
  - CVE-2021-3185
credit:
  - John Smith
symbols:
  - Type.MethodA
  - MethodB
versions:
  # The vulnerability is present in all versions since version v0.2.0.
  - introduced: v0.2.0
  # The vulnerability is present in all versions up to version v0.2.5.
  - fixed: v0.2.5.
additional_packages:
  # Major versions must be explicitly specified
  - module: github.com/example/module/v2
    symbols:
      - MethodB
    versions:
      - fixed: v2.5.0
  - module: github.com/example/module/v3
    symbols:
      - MethodB
    versions:
      - introduced: v3.0.1
links:
  - commit: https://github.com/example/module/commit/aabbccdd
  - pr: https://github.com/example/module/pull/10
  - context:
      - https://www.openwall.com/lists/oss-security/2016/11/03/1
      - https://github.com/example/module/advisories/1
```
