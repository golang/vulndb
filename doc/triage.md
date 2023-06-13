# Handling Go Vulnerability Reports

This document explains how we handle vulnerability issue triage in the
[x/vulndb issue tracker](http://github.com/golang/vulndb/issues).

## Reports

All vulnerabilities in the Go vulnerability database are currently stored as a
YAML file in the data/reports or data/excluded directory.

For a detailed explanation of the report format and style guide, see
[doc/format.md](format.md).

## Issue States

Any open issue should be in one of the following states:

- New (no label)
- Needs investigation
- Needs report
- Excluded
- Out of scope

Maintainers of the Go vulndb move issues from one state to another.
The intent behind these explicit states is to describe the (minimum)
next steps required to bring the issue to resolution.

### New (untriaged)

The issue has been filed by the vulndb worker or an external reporter.

The issue will have the title: `x/vulndb: potential Go vuln in <module/package>: <CVE ID and or GHSA ID>`.

To transition from this state, do one of the following:

- Label the issue as `NeedsInvestigation`, and discuss the issue with the team.
- Label the issue as `excluded: REASON`, and use the `vulnreport create-excluded` command
  to create a CL.
- Label the issue as `NeedsReport`, and use the `vulnreport` tool to assist in creating a CL.
- Label the issue as `excluded: OUT_OF_SCOPE` and close the issue.
- Label the issue as `duplicate` and close the issue.

### Needs Investigation

Label: `NeedsInvestigation`

This state is used when it is not clear how to proceed. (Otherwise, an
issue can move straight to one of the other states.)

Make a plan to discuss the issue with the team to determine a course of action.

### Needs Report

Label: `NeedsReport`

The issue has been confirmed to be an in-scope Go vulnerability, and a report
needs to be added to `data/reports`.

### Excluded

Label: `excluded: REASON` where REASON is one of the possible
[excluded reasons](https://go.dev/security/vuln/database#excluded-reports).

The issue represents a reported vulnerability, but is not in scope for the
main `data/reports` folder. An "excluded" report needs to be added to `data/excluded`.

### Out-of-scope

Label: `excluded: OUT_OF_SCOPE` or `duplicate`.

The issue is out of scope for both the `data/reports` and `data/excluded` folders.
For example, it is an issue mistakenly posted to the tracker (`excluded: OUT_OF_SCOPE`)
or a duplicate (`duplicate`) of another issue.

The issue can be closed without further action.

## Adding new reports

### One-time setup

1. Clone the x/vulndb repository: `git clone https://go.googlesource.com/vulndb`.
2. Get a [GitHub access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) with scope `repo: public_repo`
   (follow instructions for "personal access token (classic)").

   Store the token in a file, e.g., `~/.github-token`, and run:
   ``export VULN_GITHUB_ACCESS_TOKEN=`cat ~/.github-token` `` (you can also store
   this command in a `~/.bashrc` file or similar).
3. Run `go install ./cmd/vulnreport` to install the latest version of vulnreport tool

### Add a new report (label `NeedsReport`)

1. Sync your git repo, re-install the vulnreport tool, and create a fresh branch.
2. From the repo root, run `vulnreport create <GitHub issue number>`.
   The `vulnreport` tool will create a YAML report template for the CVE or GHSA at the
   specified GitHub issue number. This command works for both regular reports
   and excluded reports. It also accepts multiple Github issue numbers (space
   separated), and Github issue ranges (e.g., `1000-1010`).
3. Edit the report file template, following the guidance in [doc/format.md](format.md).
   A few tips:
   - If a person or organization is given credit in the CVE or GHSA, add the
      name to the "credit" field. Otherwise, delete the field.
   - In the "vulnerable_at" field, put the highest version just before the
      vuln is fixed. The pkgsite versions page can help with the list of
      versions. The GitHub UI also makes it easy to list tags (click "Code",
      then the dropdown that shows the current branch, then "Tags"). Walk the
      versions backwards from the fixed one to find the highest that doesn't
      contain the fix. (It might not be the immediately preceding version.)
   - Add vulnerable functions to the "symbols" list by reading the CVE,
      the fixing CLs, and the code at the vulnerable version you chose above.
4. From the repo root, run `vulnreport fix <GitHub issue number>`.
   This will lint the report, add exported symbols, and convert the YAML to OSV.
5. Once any errors are fixed, run `vulnreport commit <GitHub issue number>`.
   This will create a git commit containing the new files with a standard commit message.
   Commits are to the local git repository. The `vulnreport commit` command
   also accepts multiple space-separated issue numbers, and will create a separate commit for
   each report.
6. Send the commit for review and approval. See the Go
   [contribution guide](https://go.dev/doc/contribute) for sending a change on
   Gerrit.
7. If you make changes to the report during review, re-run
   `vulnreport fix <GitHub issue number>` before re-mailing to update the OSV
   and make sure the report is still valid.

### Batch add excluded reports (label `excluded: REASON`)

1. Sync your git repo, re-install the vulnreport tool, and create a fresh branch.
2. Run `vulnreport create-excluded`.
   This will batch create YAML reports for all issues with the
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
The worker doesn't always detect this automatically, so it is a good idea to
grep the `/data` directory of this repo for the module path and read the
report to see if the vulns are the same.

If the issue is indeed a duplicate:

1. Apply the label `duplicate` to the issue.
2. Find the duplicate issue (say it is #NNN) in the issue tracker, and on the
   current issue, write the comment "Duplicate of #NNN". (No period after the
   number.)
3. If a report has already been created for #NNN:
   1. Find the report yaml file (say GO-YYYY-NNNN.yaml) in `data/reports`, and add
   the duplicate IDs to the `cves` or `ghsas` section, as appropriate.
   Running `vulnreport fix` can sometimes find the IDs automatically.
   (If the duplicate IDs are already present, close the GH issue.)
   2. On a new branch, run `vulnreport -up commit NNN` to update generated files
   and create a commit. Edit the generated commit message so that it includes
   the words "add aliases".
   You can also add "Fixes #DDDD" (the number of the duplicate issue) to the
   commit message, or close it manually.
   3. Mail the commit.
4. If no report has been created for #NNN yet, make sure the duplicate ID is present
   somewhere in issue #NNN for reference, and close the duplicate issue.

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

The command `vulnreport -up commit NNN` can be used to create a more sensible
commit message when committing an updated report.

## Frequent issues during triage

This section describes frequent issues that come up when triaging vulndb reports.

### vulnreport cgo failures

When `vulnreport fix` fails with an error message like

```txt
/path/to/package@v1.2.3/foo.go:1:2: could not import C (no metadata for C)
````

a frequent cause is the local machine missing `C` library headers causing
typechecking of cgo packages to fail. The easiest workaround is to use
a machine with the development headers installed or to install them.

Commonly missing packages include:

- libgpgme-dev
- libdevmapper-dev
