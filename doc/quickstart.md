# Go Vulnerability Database Quickstart

This document is a quick guide our new (evolving) process for handling vulnerability issue triage in the
[x/vulndb issue tracker](http://github.com/golang/vulndb/issues).

Other useful docs:
 - [Triage](triage.md)
 - [Report format reference](format.md)
 - [Vulnreport reference](vulnreport.md)

## Quickstart

### Triage

NEW: To triage all issues, create reports that can be created automatically,
and commit them, run:

```sh
./devtools/vulntriage.sh
```

0. Assign any unlabeled, unassigned issues on the tracker to yourself.
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

### Check for duplicates and not Go code

1.  For all reports marked `duplicate`, quickly double-check if the label is correct (it usually is).

   * If correct: close the issue.
   * If incorrect: remove the `duplicate` label, delete the duplicate comment, and ensure the
   `triaged` label is present.

2. For all reports marked `possibly not Go`, determine if the label is correct by investigating the report to see if the vulnerability affects Go code.

   * If correct: replace the `possibly not Go` label with the `excluded:NOT_GO_CODE` label.
   * If incorrect: remove the `possibly not Go` label and ensure the `triaged` label is present.

   Once labeled, you can create excluded reports for these using the `vulnreport create-excluded` command (See [triage guide](triage.md#batch-add-excluded-reports-label-excluded-reason) for usage).

### Add reports

All remaining open issues marked `triaged` now need standard reports.

Issues marked `triaged` (but not `high priority` or `possible duplicate`)
need an UNREVIEWED report. Issues marked `triaged` and `high priority`
need a REVIEWED report.

1. Batch create all reports assigned to you:

 ```bash
   $ vulnreport -user=<github_username> create
 ```

2. Check for UNREVIEWED reports with lint errors, and edit these reports
to fix the errors. (Run `vulnreport lint NNN` to check if the errors are
fixed). If there are no errors, do not edit the report.
3. Batch fix and commit the UNREVIEWED reports:

 ```bash
   $ vulnreport -status=UNREVIEWED -batch=20 commit
 ```
4. For each REVIEWED report:
   a. Fill in all the TODOs using [doc/format.md](format.md) as a guide.
   b. Fix the report and add derived files:

      ```bash
      $ vulnreport fix NNN
      ```

   c. If `fix` fails, edit the report until it succeeds.
   d. Commit the report:

      ```bash
      $ vulnreport commit NNN
      ```

6. Mail the CLs and add a team member as a reviewer.

## One-time setup

1. Clone the x/vulndb repository: `git clone https://go.googlesource.com/vulndb`.
2. Get a [GitHub access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) with scope `repo: public_repo`
   (follow instructions for "personal access token (classic)").

   Store the token in a file, e.g., `~/.github-token`, and run:
   ``export VULN_GITHUB_ACCESS_TOKEN=`cat ~/.github-token` `` (you can also store
   this command in a `~/.bashrc` file or similar).
3. From the repo root, run `go install ./cmd/vulnreport` to install the latest
   version of vulnreport tool.