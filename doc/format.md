# Vulnerability Report Format & Style Guide

The Go vulnerability report format is used to generate JSON files
served to the the vulnerability database.

This file format is meant for internal use only, and is subject to
change without warning. See [go.dev/security/vuln/database](https://go.dev/security/vuln/database)
for information on the Go Vulnerability database API.

This page documents the internal YAML file format.

## `packages`

type [[]Package](#type-package)

**required**

Information on each package affected by the vulnerability.

Include every importable package containing a root vulnerable symbol.
If `"internal/foo".F` is vulnerable and `"foo".F` calls it, only include
the innermost (internal) package.

If a vulnerability occurs in multiple major versions of a module,
include an entry for each major version.

## Type **Package**

### `module`

type `string`

**required** 

The module path of the vulnerable module.

Use `"std"` for vulnerabilities in the standard library.

Use `"cmd"` for vulnerabilities in the Go tools (`cmd/...`).

### `package`

type `string`

**required (if different from `module`)**

The import path of the vulnerable package.

Omit this field if the package name is identical to the module name.

### `symbols`

type `[]string`

The symbols affected by this vulnerability.

If included, only programs which use these symbols will be marked as
vulnerable. If omitted, any program which imports this module will be
marked vulnerable.

These should be the symbols initially detected or identified in the CVE
or other source.

### `derived_symbols`

type `[]string`

Derived symbols that are calculated from `symbols`,
such as by static analysis tools like `govulncheck`.

This is generated automatically by the `vulnreport fix` command.
Don't edit this field manually.

Potentially, the set of derived symbols can differ with the module
version. We don't attempt to capture that level of detail. Most of the
values of `derived_symbols` as of this writing were obtained from a
module version that was just prior to the version that the report
listed as fixed.

### `versions`

type [`[]VersionRange`](#type-versionrange)

The version ranges in which the package is vulnerable.

If omitted, it is assumed that _every_ version of the module is
vulnerable.

Versions must be SemVer 2.0.0 versions, with no "v" or "go" prefix.
Version ranges must not overlap.

Don't expend effort finding the first `introduced` version unless
it's obvious.

The version ranges in announcements, CVE text, GHSAs, and so forth are
frequently wrong. Always verify the fixed version from the repository history.

If the vulnerability is fixed in multiple minor versions, define
non-overlapping version ranges thats describe the affected revisions.
For example, for a fix in 1.17.2, 1.18.4, and 1.19.0:

```
- fixed: 1.17.2
- introduced: 1.18.0
  fixed: 1.18.4
```

Note that we don't need to mention 1.19.0 in the version ranges, since it
comes after 1.18.4.

### Type **VersionRange**

#### `introduced`

type `string`

The version at which the vulnerability was introduced.

If this field is omitted, it is assumed that every version, from the
initial commit, up to the `fixed` version is vulnerable.

#### `fixed`

type `string`

The version at which the vulnerability was fixed.

If this field is omitted, it is assumed that every version since the
`introduced` version is vulnerable.

## `vulnerable_at`

The version (see above for format) at which the vulnerable symbols
were obtained. Ideally, this is the version just prior to the fix.

## `description`

type `string`

**required**

A textual description of the vulnerability and its impact. Should be
wrapped to 80 columns. Does not use Markdown formatting.

The first paragraph should be a short, succinct description of the
nature and impact of the vulnerability, ideally one line.  Assume
the person reading this knows what the vulnerable package does.

Use additional paragraphs to describe the issue in more detail as
necessary.

Use the present tense: "This is vulnerable" rather than "this was
vulnerable".

## `published`

type `time.Time`

Date the report was added to the vulnerability database.
This is normally determined from the git repository history, and
does not need to be set in the report YAML except when the first
commit of the report YAML doesn't match the publication date.

Older reports moved from a previous location have this set.

## `last_modified`

type `time.Time`

Last time the report was changed. This is normally determined from
the repository history, and does not need to be set in the report
YAML.

## `cves`

type `[]string`

The Common Vulnerabilities and Exposures (CVE) ID(s) for the
 vulnerability.

## `ghsas`

type `[]string`

The GitHub Security Advisory (GHSA) IDs for the vulnerability.

## `credit`

The name of the person/organization that discovered/reported the
vulnerability.

This should be filled in for Go project reports (standard library,
golang.org/x, etc.). Use the text from the golang-announce email
when available.

For third-party reports, if `vulnreport create` finds CVE or GHSA metadata, use
that. Also, look for a "Credits" heading on the GHSA report linked from the
GitHub issue. Otherwise, it's okay to leave this blank.


## `references`

type [`[]Reference`]

Links to further information about the vulnerability.

Include a `FIX` link to the fix pull request, Gerrit code review, or commit.
No need to link both the PR and the commit.
Prefer to link to the PR or code review rather than the commit.

Don't include links to CVEs and GHSAs just because they exist.
(That's what the cve/ghsa fields are for.)

DO include an `ADVISORY` link to an authoritative *first-party*
advisory when one exists.
If the first-party advisory is a GHSA, then link to that.
If the first-party advisory is a CVE, then link to the CVE page on
nvd.nist.gov/vuln.

Include a `REPORT` link to a first-party bug or issue when one exists.

Don't include links to random third-party issue trackers (e.g.,
Debian announcements). CVEs often contain a bunch of random links
of dubious value; be aggressive in pruning these out.

## Type **Report**

The internal representation of a `Report` is a struct with `Type`
and `URL` fields. For convenience, the YAML representation is a
single-element map from type to URL. For example:

```
references:
  - fix: https://go.dev/cl/25010
  - report: https://go.dev/issue/16405
```

### `type`

type `string`

The type of reference, as in the
[OSV references field](https://ossf.github.io/osv-schema/#references-field).

OSV types are upper-case, but the type in the YAML should be lower case.

Types we use:

    * `ADVISORY`: A link to an authoritative, first-party advisory.

    * `ARTICLE`: An article or blog post about the vulnerability.

    * `REPORT`: A bug or issue tracker link.

    * `FIX`: A link to the PR/CL which fixes the vulnerability.

    * `PACKAGE`: The home page for the package.
      (We usually do not include this.)

    * `EVIDENCE`: A demonstration of the vulnerability.
      (We usually do not include this.)

    * `WEB`: Anything that doesn't fit into the above.

### `url`

type `string`

The URL.

## `excluded`

type `string`

A reason the report is excluded from the database.

When a CVE or GHSA is evaluated and determined to be out of scope
for the Go Vulnerability Database, the reason for excluding it may
be recorded in a report. This report should include a value for the
`excluded` enum (this field) as well as a list of CVEs and/or GHSAs.

Excluded reports are placed in the `excluded/` directory.

Valid values are:

    * `NOT_GO_CODE`: The vulnerability is not in a Go package, and
      cannot affect any Go packages. (For example, a vulnerability in
      a C++ library.)

    * `NOT_IMPORTABLE`: The vulnerability occurs in package `main`,
      an `internal/` package only imported by package `main`, or some
      other location which can never be imported by another module.

    * `EFFECTIVELY_PRIVATE`: While the vulnerability occurs in a Go
      package which can be imported by another module, the package is
      not intended for external use and is not likely to ever be imported
      outside the module in which it is defined.

    * `DEPENDENT_VULNERABILITY`: This vulnerability is a subset of another
      vulnerability in the database. For example, if package A contains a
      vulnerability, package B depends on package A, and there are separate
      CVEs for packages A and B, we might mark the report for B as a dependent
      vulnerability entirely superseded by the report for A.

    * `NOT_A_VULNERABILITY`: While a CVE or GHSA has been assigned,
      there is no known vulnerability associated with it.

## Example Reports

### Third-party example report

```yaml
packages:
  - module: github.com/example/module
    package: github.com/example/module/package
    symbols:
      - Type.MethodA
      - MethodB
    versions:
      # The vulnerability is present in all versions since version v0.2.0.
      - introduced: 0.2.0
      # The vulnerability is present in all versions up to version v0.2.5.
      - fixed: 0.2.5
    # Major versions must be explicitly specified
  - module: github.com/example/module/v2
    symbols:
      - MethodB
    versions:
      - fixed: 2.5.0
  - module: github.com/example/module/v3
    symbols:
      - MethodB
    versions:
      - introduced: 3.0.1
description: |
  A description of the vulnerability present in this module.

  The description can contain newlines, and a limited set of markup.
cves:
  - CVE-2021-3185
ghsas:
  - GHSA-1234-5678-9101
credit:
  - John Smith
references:
  - advisory: https://github.com/example/module/advisories/1
  - fix: https://github.com/example/module/pull/10
  - web: https://www.openwall.com/lists/oss-security/2016/11/03/1
```

### Standard library example report

```yaml
packages:
  - module: std
    package: a/package
    symbols:
      - pkg.ASymbol
    versions:
      - introduced: 1.14
        fixed: 1.14.12
      - introduced: 1.15
        fixed: 1.15.5
description: |
    A description.
cves:
  - CVE-2020-12345
references:
  - fix: https://go.dev/cl/12345
  - report: https://go.dev/issue/01010
  - web: https://groups.google.com/g/golang-announce/c/123456
```
