# Vulnerability Report Format & Style Guide

The Go security team uses an internal YAML format to create vulnerability
reports, which are automatically converted to OSV JSON and served to the
vulnerability database at [vuln.go.dev](https://vuln.go.dev).

The YAML format is subject to change without warning and should not be
relied on by external tools. (See [go.dev/security/vuln/database](https://go.dev/security/vuln/database) for information on the public Go Vulnerability
database API and the OSV schema.)

This page documents the fields of the internal YAML file format.

## `id`

type `string`

**required**

The unique Go identifier assigned to this report.

This is automatically assigned via `vulnreport create`. It should be of
the form `GO-YYYY-NNNN` where `YYYY` is the year the report was created,
and `NNNN` is the x/vulndb issue tracker number associated with the report.

## `modules`

type `[]module`

**required**

Information on each Go module affected by the vulnerability.

### `module.module`

type `string`

**required**

The module path of the vulnerable module.

Use `"std"` for vulnerabilities in the standard library.

Use `"cmd"` for vulnerabilities in the Go tools (`cmd/...`).

### `modules.versions`

type `[]version`

The version ranges in which the package is vulnerable.

If omitted, it is assumed that _every_ version of the module is
vulnerable.

Versions must be SemVer 2.0.0 versions, with no "v" or "go" prefix.
Version ranges must not overlap.

Don't expend effort finding the first `introduced` version unless
it's obvious.

The version ranges in announcements, CVE text, GHSAs, and so forth are
frequently wrong. Always verify the fixed version from the repository history.

If the vulnerability is fixed in multiple minor versions, define sorted,
non-overlapping version ranges thats describe the affected revisions.
For example, for a fix in 1.17.2, 1.18.4, and 1.19.0:

```yaml
- fixed: 1.17.2
- introduced: 1.18.0
  fixed: 1.18.4
```

Note that we don't need to mention 1.19.0 in the version ranges, since it
comes after 1.18.4.

#### `version.introduced`

type `string`

The version at which the vulnerability was introduced.

If this field is omitted, it is assumed that every version, from the
initial commit, up to the `fixed` version is vulnerable.

#### `version.fixed`

type `string`

The version at which the vulnerability was fixed.

If this field is omitted, it is assumed that every version since the
`introduced` version is vulnerable.

## `module.vulnerable_at`

type `string`

The version at which the vulnerable symbols were obtained. Ideally, this
is the version just prior to the fix.

## `module.vulnerable_at_requires`

type `[]string`

List of module@version to require when performing static analysis.
It is rare that we need to specify this.

Example from [GO-2021-0072](../data/reports/GO-2021-0072.yaml):

```yaml
vulnerable_at_requires:
  - github.com/Sirupsen/logrus@v1.0.6
```

### `module.packages`

type `[]package`

**required**

Information on each package affected by the vulnerability.

Include every importable package containing a root vulnerable symbol.
If `"internal/foo".F` is vulnerable and `"foo".F` calls it, only include
the innermost (internal) package.

If a vulnerability occurs in multiple major versions of a module,
include an entry for each major version.

#### `package.package`

type `string`

**required**

The import path of the vulnerable package.

#### `package.symbols`

type `[]string`

The symbols affected by this vulnerability.

If included, only programs which use these symbols will be marked as
vulnerable. If omitted, any program which imports this module will be
marked vulnerable.

These should be the symbols initially detected or identified in the CVE
or other source.

#### `package.derived_symbols`

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

#### `package.skip_fix`

type `string`

A text justification for why static analysis should not be performed
on this package (perhaps because it causes an error). It is rare
that we need to specify this.

## `summary`

type `string`

**required**

A short (<=100 characters) textual description of the vulnerability,
usually of the form "PROBLEM in MODULE(s)", e.g:
`summary: "Man-in-the-middle attack in golang.org/x/crypto/ssh`.

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

(Handled automatically, do not edit manually)

Date the report was added to the vulnerability database.
This is normally determined from the git repository history, and
does not need to be set in the report YAML except when the first
commit of the report YAML doesn't match the publication date.

Older reports moved from a previous location have this set.

## `last_modified`

type `time.Time`

(Handled automatically, do not edit manually)

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

## `credits`

type `[]string`

The name(s) of the person/organization that discovered/reported the
vulnerability.

This should be filled in for Go project reports (standard library,
golang.org/x, etc.). Use the text from the golang-announce email
when available.

For third-party reports, if `vulnreport create` finds CVE or GHSA metadata, use
that. Also, look for a "Credits" heading on the GHSA report linked from the
GitHub issue. Otherwise, it's okay to leave this blank.

## `references`

type `[]reference`

Links to further information about the vulnerability.

Include a `fix` link to the fix pull request, Gerrit code review, or commit.
No need to link both the PR and the commit.
Prefer to link to the PR or code review rather than the commit.

Don't include links to CVEs and GHSAs just because they exist.
(That's what the cve/ghsa fields are for.)

DO include an `advisory` link to an authoritative *first-party*
advisory when one exists.
If the first-party advisory is a GHSA, then link to that.
If the first-party advisory is a CVE, then link to the CVE page on
nvd.nist.gov/vuln.

Include a `report` link to a first-party bug or issue when one exists.

Don't include links to random third-party issue trackers (e.g.,
Debian announcements). CVEs often contain a bunch of random links
of dubious value; be aggressive in pruning these out.

The internal representation of a `Reference` is a struct with `Type`
and `URL` fields. For convenience, the YAML representation is a
single-element map from type to URL. For example:

```yaml
references:
  - fix: https://go.dev/cl/25010
  - report: https://go.dev/issue/16405
```

### `reference.type`

type `string`

The type of reference, as in the
[OSV references field](https://ossf.github.io/osv-schema/#references-field).

OSV types are upper-case, but the type in the YAML should be lower case.

Types we use:

* `ADVISORY`: A link to an authoritative, first-party advisory.
* `ARTICLE`: An article or blog post about the vulnerability.
* `REPORT`: A bug or issue tracker link.
* `FIX`: A link to the PR/CL which fixes the vulnerability.
* `PACKAGE`: The home page for the package. (We usually do not include this.)
* `EVIDENCE`: A demonstration of the vulnerability. (We usually do not include this.)
* `WEB`: Anything that doesn't fit into the above.

### `reference.url`

type `string`

The URL of the reference.

## `cve_metadata`

type `cve_metadata`

Information used to generate a CVE record based on this report. This
should be populated only if the Go CNA assigned the CVE for this report.

### `cve_metadata.id`

type `string`

The CVE ID assigned by the Go CNA for this report.

### `cve_metadata.cwe`

type `string`

The [CWE](https://cwe.mitre.org/index.html) most closely associated
with this vulnerability, of the form "CWE-XXX: Description".

### `cve_metadata.description`

type `string`

The description of the vulnerability to use in the CVE record. If blank,
the top-level description is used.

This was used to preserve existing descriptions. For new reports, this
does not need to be set.

### `cve_metadata.references`

type `[]string`

References that should be published in the CVE record, but not the OSV
record. This is used to preserve references added by the CVE program,
and is rarely used.

Example: [GO-2022-0476](../data/reports/GO-2022-0476.yaml)

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

* Standard library: [GO-2021-0067](../data/reports/GO-2021-0067.yaml)
* Toolchain: [GO-2021-0068](../data/reports/GO-2021-0068.yaml)
* x/ repo: [GO-2020-0012](../data/reports/GO-2020-0012.yaml)
* Third-party: [GO-2021-0075](../data/reports/GO-2021-0075.yaml)
* Excluded:[GO-2022-0559](../data/excluded/GO-2022-0559.yaml)
