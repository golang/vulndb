# Handling Go Vulnerability Reports

This document explains how we handle vulnerability issue triage in the
[x/vulndb issue tracker](http://github.com/golang/vulndb/issues).

## Reports

All vulnerabilities in the Go vulnerability database are currently stored as a
YAML file in the data/reports or data/excluded directory.

Each vulnerability is given an ID with the format GO-YYYY-NNNN.

- The YYYY component corresponds to the year in which the vulnerability was
  published.
- The NNNN component is a unique ID for that vulnerability, which is generated
  using the GitHub issue ID for that vulnerability.

For a detailed explanation of the report format, see [doc/format.md](format.md).

## Issue States

Any issue must be in one of the following states. Maintainers of the Go vulndb
move issues from one state to another. The intent behind these explicit states
is to describe the (minimum) next steps required to bring the issue to
resolution.

Issues are intended to move between these states:

```txt
                                       +-------------+
                                       |             |   via CL
                       +-------------->| NeedsReport +----------+
                       |               |             |          |
                       |               +-------------+          |
                +---------+----------+                          v
                |                    |                        Closed
 NeedsTriage -->| NeedsInvestigation |
                |      (optional)    |  +------------+           ^
                +----------+---------+  |            |           |
                       |                | excluded:  |           | 
                       |                | REASON     | +---------+
                       +--------------->|            |    via CL
                                        +------------+
```

### NeedsTriage (New)

- The issue has been filed by the vulndb worker
- The issue will have the title:
  `x/vulndb: potential Go vuln in <module/package>: <CVE ID and or GHSA ID>`
- To transition from this state, someone must:

  - Label the issue as `excluded: REASON`, and make a CL
  - Label the issue as `NeedsReport`, and make a CL
  - Label the issue as `NeedsInvestigation`, and CC people who might be best to
    investigate the issue and provide further context.

### Needs Investigation

- The issue has the label `NeedsInvestigation`
- This state is used by the triager when it is not clear to them how to
  proceed. Otherwise, an issue can move straight from NeedsTriage to one of the
  other states.
- Someone (CC-ed) must examine the issue and confirm whether or not it is a Go
  vuln.

### Needs Report

- The issue has been confirmed to be an in-scope Go vulnerability, and a report
  needs to be added to `data/reports`.
- The issue has the label `NeedsReport`

### Excluded

- The issue has been confirmed to be out of scope for the Go vulnerability
  database.
- An excluded report needs to be added to `data/excluded`.
- The issue has the label `excluded: REASON` where REASON is one of the possible
  [excluded reasons](https://go.dev/security/vuln/database#excluded-reports).

## Adding a new report

If an issue is labeled with `NeedsReport` or `excluded: REASON`, you can add a
new report to the database by following these steps:

1. Make sure the issue is assigned to you.
2. Clone the x/vulndb repository: `git clone https://go.googlesource.com/vulndb`
3. Run `go install ./cmd/vulnreport` to install the vulnreport tool.
4. You will need a
   [GitHub access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
   with scope `repo: public_repo`.

   Store the token in a file, e.g., `~/.github-token`, and run:
   ``export VULN_GITHUB_ACCESS_TOKEN=`cat ~/.github-token` `` (you can also store
   this command in a `~/.bashrc` file or similar).
5. Run `vulnreport create <GitHub issue number>`.
   vulnreport will create a YAML report template for the CVE or GHSA at the
   specified GitHub issue number. This command works for both regular reports
   and excluded reports. It also accepts multiple Github issue numbers (space
   separated), and Github issue ranges (e.g., `1000-1010`).
6. Edit the report file template.
7. Run `vulnreport commit [<report file> | <Github issue number>]`. This will
   lint the report, add exported symbols, convert the YAML to OSV, and commit
   the new files with a standard commit message. The `vulnreport commit` command
   also accepts multiple space-separated files/issue numbers, and will create a
   separate commit for each report.

### Standard Library Reports

When adding a vulnerability report about the standard library, ensure that the
references section follows this format:

  ```yaml
  references:
  - report: https://go.dev/issue/<#>
  - fix: https://go.dev/cl/<#>
  - web: https://groups.google.com/g/golang-announce/c/<XXX>/<YYY>
  ```

You can find these links in the golang-announce@ email for the security release
fixing this vulnerability.

**Report:** The Github issue will be listed in the golang-announce@ email.

**Fix:** The PR will be a go.dev/cl/<#> link, found as a gopherbot comment on
the issue for the vulnerability.

**Web:** The golang-announce email link.

## Updating a report

Occasionally, we will receive new information about a Go vulnerability and want
to update the existing report.

In that case, reopen the issue for the report to discuss the change, rather
than create a new issue.
