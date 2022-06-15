# Handling Go Vulnerability Reports

This document explains how we handle vulnerability issue triage in the
[x/vulndb issue tracker](http://github.com/golang/vulndb).

## Reports

All vulnerabilities in the Go vulnerability database are currently stored as a
YAML file in the reports/ directory.

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

```
                                    +-------------+
                                    |             |   via CL
                      +------------>| NeedsReport +----------+
                      |             |             |          |
                      |             +-------------+          |
            +---------+--------+                             v
            |                  |                           Closed
 New   ---->|NeedsInvestigation|
            |    (optional)    |    +------------+           ^
            +----------+-------+    |            |           |
                       |            | NotGoVuln  +-----------+
                       +----------->|            |
                                    +------------+
```

### New

- The issue has been filed by the vulndb worker
- The issue will have the title: `x/vulndb: potential Go vuln in <module/package>: <CVE ID>`
- To transition from this state, someone must:

  - Label the issue as NotGoVuln, and close the issue.
  - Label the issue as NeedsReport, and make a CL
  - Label the issue as NeedsInvestigation, and CC people who might be best to
    investigate the issue and provide further context.

### Needs Investigation

- The issue has the label `NeedsInvestigation`
- This state is used by the triager when it is not clear to them how to
  proceed. Otherwise, an issue can move straight from New to one of the other
  states.
- Someone (CC-ed) must examine the issue and confirm whether or not it is a Go vuln

### Needs Report

- The issue has been confirmed to be a Go vulnerability, an a report needs to
  be added to the vulndb for this CVE.
- The issue has the label `NeedsReport`

### Not Go Vuln

- The issue has been confirmed to not be a Go vulnerability.
- The issue is resolved and can be closed.
- The `NotGoVuln` label should be applied at the time the issue is closed for
  tracking purposes (such as data on how to improve the automatic triager).

## Adding a new report

If an issue is labeled with `NeedsReport` and is not assigned to anyone, you
can add a new report to the database by following these steps:

1. Assign the issue to yourself.
2. Clone the x/vulndb repository: `git clone https://go.googlesource.com/vulndb`
3. You will need a
   [GitHub access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
   with scope `repo: public_repo`.

   Run `export VULN_GITHUB_ACCESS_TOKEN=<Github access token>`   
4. Run `go run ./cmd/vulnreport create <GitHub issue number>`.
   vulnreport will download the github.com/CVEProject/cvelist repository and
   create a YAML report template for the CVE at the specified GitHub issue
   number.
5. Edit the report file template.
6. Run `go run ./cmd/vulnreport commit <report file>`. This will lint the
   report and commit it with a standard commit message.

### Standard Library Reports

When adding a vulnerability report about the standard library, ensure that the  links  section
follows this format:

  ```
  - links:
  - pr:
    - https://go.dev/cl/<#>
  - commit:
    - https://go.googlesource.com/<repo>/+/<commit>
  - context:
    - https://go.dev/issue/<#>
    - golang-announce@ email
  ```

You can find these links in the golang-announce@ email for the security release fixing this vulnerability.

**PR:** The PR will be a go.dev/cl/<#> link, found as a gopherbot comment on the issue for the vulnerability.

**Commit:** The commit is a go.googlesource.com link, which can be found on the CL page (see
[screenshot](https://user-images.githubusercontent.com/51683211/156475820-f671bcf5-d21e-4a25-ad3c-ee047ac91b91.png)).

**Issue:** The issue will be listed in the golang-announce@ email.

## Updating a report

Occasionally, we will receive new information about a Go vulnerability and want
to update the existing report.

In that case, reopen the issue for the report to discuss the change, rather
than create a new issue.
