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
   [GitHub access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) with scope `repo: public_repo`
   (follow instructions for "personal access token (classic)").

   Store the token in a file, e.g., `~/.github-token`, and run:
   ``export VULN_GITHUB_ACCESS_TOKEN=`cat ~/.github-token` `` (you can also store
   this command in a `~/.bashrc` file or similar).

### If the report is labeled `NeedsReport`

1. From the repo root, run `vulnreport create <GitHub issue number>`.
   vulnreport will create a YAML report template for the CVE or GHSA at the
   specified GitHub issue number. This command works for both regular reports
   and excluded reports. It also accepts multiple Github issue numbers (space
   separated), and Github issue ranges (e.g., `1000-1010`).
2. Edit the report file template.
3. From the repo root, run `vulnreport commit [<report file> | <GitHub issue number>]`.
   (Example: `vulnreport commit 1623`.)
   This will lint the report, add exported symbols, convert the YAML to OSV, and commit
   the new files with a standard commit message. Commits are to the local git
   repository. The `vulnreport commit` command also accepts multiple
   space-separated files/issue numbers, and will create a separate commit for
   each report.
4. Send the commit for review and approval. See the Go
   [contribution guide](https://go.dev/doc/contribute) for sending a change on
   Gerrit.
5. If you make changes to the report during review, run
   `vulnreport fix <GitHub issue number>` before re-mailing to update the OSV
   and perform other useful actions.


### If the report is labeled `excluded: REASON`

1. Start a new branch in your vuldb clone for the commit that the next step
   will create.
2. Run `vulnreport create-excluded`.
   vulnreport will batch create YAML reports for all issues with the
   `excluded: REASON` label. If there is an error creating any given report,
   the skipped issue number will be printed to stdout and that issue will have
   to be created manually with `vulnreport create <Github issue number>`.
   (see steps 2-4 above for more information).
   Additionally, `create-excluded` will automatically create a single commit for
   all successful reports.
3. Send the commit for review and approval. See the Go
   [contribution guide](https://go.dev/doc/contribute) for sending a change on
   Gerrit.

## Handling duplicates

Sometimes an issue describes a vulnerability that we already have a report for.
The worker doesn't (yet) detect this automatically, so it is a good idea to
grep the `/data` directory of this repo for the module path and read the
report to see if the vulns are the same.

If the issue is indeed a duplicate:

1. Apply the label `duplicate` to the issue.

2. Find the duplicate issue (say it is #NNN) in the issue tracker, and on the
   current issue, write the comment "Duplicate of #NNN". (No period after the
   number.)

3. Find the corresponding report yaml file (say GO-YYYY-NNNN.yaml) in
   `data/reports`, and add the duplicate IDs to the `cves` or `ghsas` section,
   as appropriate. (If the duplicate IDs are already present, close the GH
   issue.)

4. On a new branch, run `vulnreport -up commit NNN` to update generated files
   and create a commit. Edit the generated commit message so that it includes
   the words "add aliases".
   You can also add "Fixes #DDDD" (the number of the duplicate issue) to the
   commit message, or close it manually.

5. Mail the commit.

## Standard Library Reports

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

## Frequent issues during triage

This section describes frequent issues that come up when triaging vulndb reports.

### vulnreport cgo failures

When `vulnreport fix` fails with an error message like
```
/path/to/package@v1.2.3/foo.go:1:2: could not import C (no metadata for C)
````
a frequent cause is the local machine missing `C` library headers causing
typechecking of cgo packages to fail. The easiest workaround is to use
a machine with the development headers installed or to install them.

Commonly missing packages include:
* libgpgme-dev
* libdevmapper-dev
