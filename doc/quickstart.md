# Go Vulnerability Database Quickstart

[WORK IN PROGRESS]

This document is a quick guide our new (evolving) process for handling vulnerability issue triage in the
[x/vulndb issue tracker](http://github.com/golang/vulndb/issues).

For the original documentation, which is somewhat outdated, see our [old triage docs](triage.md).

## Quickstart

### Triage

1. If you haven't already, follow the [one-time-setup](#one-time-setup) process.
2. Sync the vulndb repo, re-install vulnreport and switch to a fresh branch, e.g.:

   ```bash
   $ cd vulndb
   $ git sync
   $ go install ./cmd/vulnreport
   $ git checkout -b reports
   ```

3. Auto-triage the outstanding issues by running

   ```bash
   $ vulnreport triage
   ```

   See [`vulnreport triage`](#vulnreport-triage) for more info
   and options for this command.
4. All triaged reports (label: `triaged`) will need a report, except for duplicates. For all reports marked `possible duplicate`, determine if
the label is correct.

   * If correct: replace the `possible duplicate` label with the `duplicate` label, add a comment exactly of the form "Duplicate of #NNN" where #NNN is number of the issue this is a duplicate of, and close the issue.
   * If incorrect: remove the `possible duplicate` label and ensure the `triaged` label is present.

5. For all reports marked `possibly not Go`, determine if the label is correct by investigating the report to see if the vulnerability affects Go code.

   * If correct: replace the `possibly not Go` label with the `excluded:NOT_GO_CODE` label.
   * If incorrect: remove the `possibly not Go` label and ensure the `triaged` label is present.

   Once labeled, you can create excluded reports for these using the `vulnreport create-excluded` command (See [the old docs](triage.md#batch-add-excluded-reports-label-excluded-reason) for usage).

   Note: the excluded labels NOT_IMPORTABLE and EFFECTIVELY_PRIVATE are being deprecated.
   The labels NOT_A_VULNERABILITY and DEPENDENT_VULNERABILITY are still acceptable, but it
   is also OK to just create an unreviewed report for these types of vulns.
6. All remaining open issues marked `triaged` now need standard reports.

### Add standard reports

1. Issues marked `high priority` need a REVIEWED report, and issues without a priority label need an UNREVIEWED report.
   * To create a reviewed report for issue #NNN, run:

      ```bash
      $ vulnreport create NNN
      ```

   * To create an unreviewed report for issue #NNN, run:

      ```bash
      $ vulnreport -unreviewed create NNN
      ```

2. Edit the report if needed. For reviewed reports, this follows the standard process. For unreviewed reports, only edit the report if it has lint/fix errors (which will be populated in the notes section).
3. Fix the report and add derived files:

   ```bash
   $ vulnreport fix NNN
   ```

4. If `fix` fails, edit the report until it succeeds.
5. Commit the report:

   ```bash
   $ vulnreport commit NNN
   ```

6. Mail the CL and add a team member as a reviewer.

## One-time setup

1. Clone the x/vulndb repository: `git clone https://go.googlesource.com/vulndb`.
2. Get a [GitHub access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) with scope `repo: public_repo`
   (follow instructions for "personal access token (classic)").

   Store the token in a file, e.g., `~/.github-token`, and run:
   ``export VULN_GITHUB_ACCESS_TOKEN=`cat ~/.github-token` `` (you can also store
   this command in a `~/.bashrc` file or similar).
3. From the repo root, run `go install ./cmd/vulnreport` to install the latest
   version of vulnreport tool.

## Issue types

There are 4 types of issues on our tracker:

1. CVEs/GHSAs created automatically by the worker
2. Direct external reports from community members
3. Suggested edits from community members
4. Placeholder issues for first-party reports

The vast majority of issues are of the first type, and this document focuses on handling these.

## `vulnreport` commands

### `vulnreport triage`

Standard usage:

```bash
$ vulnreport triage
```

This command looks at all untriaged issues to find and label:

* High-priority issues (label: `high priority`) - issues that affect modules with >= 100 importers
* Possible duplicates (label: `possible duplicate`) - issues
that may be duplicates of another issue because they share a CVE/GHSA
* Possibly not Go (label: `possibly Not Go`) - issues that possibly do not affect Go at all. This is applied to modules
for which more than 20% of current reports are marked `excluded: NOT_GO_CODE`.

Arguments:

The `vulnreport triage` command also accepts arguments,
e.g. `vulnreport triage 123` to triage issue #123, but the duplicate search only works properly when applied to all open issues.

Flags:

* `-dry`: don't apply labels to issues
* `-f`: force re-triage of issues labeled `triaged`