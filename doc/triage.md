# Handling Go Vulnerability Reports

This document explains how we handle vulnerability issue triage in the
[x/vulndb issue tracker](http://github.com/golang/vulndb/issues).

Other useful docs:
 - [Quickstart](quickstart.md)
 - [Report format reference](format.md)
 - [Vulnreport reference](vulnreport.md)

## Reports

All vulnerabilities in the Go vulnerability database are currently stored as a
YAML file in the data/reports or data/excluded directory.

For a detailed explanation of the report format and style guide, see
[doc/format.md](format.md).

## Issue types

There are 4 types of issues on our tracker:

1. CVEs/GHSAs created automatically by the worker
2. Direct external reports from community members
3. Suggested edits from community members
4. Placeholder issues for first-party reports

The vast majority of issues are of the first type, and this document focuses on handling these.

## Issue states

Any open issue should be in one of the following states:

- new (no label)
- triaged
   - standard priority (no additional label)
   - high priority
   - duplicate
   - possibly not Go
- excluded
- needs-review
- out of scope

Maintainers of the Go vulndb move issues from one state to another.
The intent behind these explicit states is to describe the (minimum)
next steps required to bring the issue to resolution.

### new (untriaged)

The issue has been filed by the vulndb worker or an external reporter.

The issue will have the title: `x/vulndb: potential Go vuln in <module/package>: <CVE ID and or GHSA ID>`.

Use the `vulnreport triage` command to triage the issue.

### triaged

Label: `triaged`

The issue has been auto-triaged.

The states are:
  - `high priority`: the issue needs a REVIEWED report
  - standard priority (no label): the issue needs an UNREVIEWED report
  - `duplicate`: we need to double-check if the issue is a duplicate
  - `possibly not Go`: we need to check if the issue does not affect Go code

### excluded

Label: `excluded: REASON` where REASON is one of the possible
[excluded reasons](https://go.dev/security/vuln/database#excluded-reports).

The issue represents a reported vulnerability, but is not in scope for the
main `data/reports` folder. An "excluded" report needs to be added to `data/excluded`.

NOTE: Some excluded reasons are being phased out. The only ones that should
be used for new reports are `NOT_GO_CODE`, `NOT_A_VULNERABILITY` and
`DEPENDENT_VULNERABILITY`.

`NOT_A_VULNERABILITY` and `DEPENDENT_VULNERABILITY` are OK to assign if
they *obviously* apply to a vulnerability, but it is also OK to simply
create an unreviewed report if you are not sure.

These can be created using the `vulnreport create-excluded` command.

### needs-review

Label: `needs-review`

The issue already has an UNREVIEWED report but it should be REVIEWED
using the `vulnreport review` command.

### out-of-scope

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
3. (To use experimental generative AI features) Get a
   [Gemini API key](https://aistudio.google.com/app/apikey).

   As above, you can store the token in a file like `~/.gemini-api-key` and use
   the environment variable `GEMINI_API_KEY`.
4. From the repo root, run `go install ./cmd/vulnreport` to install the latest
   version of vulnreport tool.

### Add a new standard report (label `triaged`)

1. Sync your git repo, re-install the vulnreport tool, and create a fresh branch.
2. From the repo root, run `vulnreport create <GitHub issue number>`.
   The `vulnreport` tool will create a YAML report template for the CVE or GHSA
   at the specified GitHub issue number.

   Tips for the `vulnreport create` command:
      - This command works for both regular (reviewed and unreviewed) reports
        and excluded reports, with no flags or configuration needed.
      - The command accepts multiple Github issue numbers (space separated),
        and Github issue ranges (e.g., `vulnreport create 99 1000-1010` would
        create reports for issue #99 and all issues from #1000 to #1010,
        skipping any that are closed, do not exist, or already have reports.)
      - Use the `-ai` flag to automatically populate a (first-draft)
        AI-generated summary and description. (See
        [Experimental Features](#experimental-features)).
      - Use the `-symbols` flag to attempt to automatically populate vulnerable
        symbols. (See [Experimental Features](#experimental-features)).
      - By default, the `create` command attempts to find a GHSA for the
        vulnerability and pull it from osv.dev. If this is not working, use
        the `-cve` flag to use the CVE (rather than the GHSA) as the default
        source.
3. Edit the report file template, following the guidance in [doc/format.md](format.md).
   A few tips:
   - If a person or organization is given credit in the CVE or GHSA, add the
      name(s) to the `credits` field. Otherwise, delete the field.
   - In the `vulnerable_at` field, put the highest version just before the
      vuln is fixed. The pkgsite versions page can help with the list of
      versions. The GitHub UI also makes it easy to list tags (click "Code",
      then the dropdown that shows the current branch, then "Tags"). Walk the
      versions backwards from the fixed one to find the highest that doesn't
      contain the fix. (It might not be the immediately preceding version.)
   - Use `vulnreport symbols <issue ID>` to auto-populate vulnerable symbols.
   - If the vulnerable symbols cannot be auto-populated, add vulnerable
     functions to the `symbols` list by reading the CVE, the fixing CLs, and the
     code at the vulnerable version you chose above.
4. Ensure all high priority reports specify either vulnerable symbols or a short
   note explaining why the entire version is marked vulnerable in the absence of
   symbols.
5. From the repo root, run `vulnreport fix <GitHub issue number>`.
   This will lint the report, add exported symbols, and convert the YAML to OSV.
6. Once any errors are fixed, run `vulnreport commit <GitHub issue number>`.
   This will create a git commit containing the new files with a standard commit
   message. Commits are to the local git repository. The `vulnreport commit`
   command also accepts multiple space-separated issue numbers, and will create
   a separate commit for each report.
7. Send the commit for review and approval. See the Go
   [contribution guide](https://go.dev/doc/contribute) for sending a change on
   Gerrit.
8. If you make changes to the report during review, re-run
   `vulnreport fix <GitHub issue number>` before re-mailing to update the OSV
   and make sure the report is still valid.

### Add a new not-Go-code report (label `possibly not Go`)

1. Remove the `possibly not Go` label
2. Check if the issue affects Go code
3. If not
   - Add `excluded: NOT_GO_CODE` label
   - Add excluded report (see next section)
4. If yes
   - Create a new standard report (see previous section)

### Batch add excluded reports (label `excluded: REASON`)

1. Sync your git repo, re-install the vulnreport tool, and create a fresh branch.
2. Run `vulnreport create-excluded`.
   This will batch create YAML reports for all issues with the
   `excluded: REASON` label. If there is an error creating any given report,
   the skipped issue number will be printed to stdout and that issue will have
   to be created manually with `vulnreport create <Github issue number>`.
   (see steps 2-4 above for more information).
   Additionally, `create-excluded` will automatically create a single commit for
   all successful reports. To skip this auto-commit step, use the `-dry` flag.
3. Send the commit for review and approval. See the Go
   [contribution guide](https://go.dev/doc/contribute) for sending a change on
   Gerrit.

## Handling duplicates

Sometimes an issue describes a vulnerability that we already have a report for.
The worker doesn't always detect this automatically.

If the issue is indeed a duplicate, find the duplicated issue (say it is #NNN).
If a report has already been created for #NNN:
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

## Experimental features

### AI-generated summary and description

The command `vulnreport suggest <Github issue number>` uses Gemini to
create AI-generated summaries and descriptions for a report. The `-i`
(interactive) flag gives the option of applying the suggestions directly
to the YAML file.

### Automatic symbol population

The command `vulnreport symbols <Github issue number>` uses the commit
link(s) in the report to find a list of possibly vulnerable functions
(functions that were present in the parent commit and were changed by
the patch). Currently, this command cannot handle pull requests or
commits with multiple parents.

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

### "awaiting analysis"

When the NIST page says "AWAITING ANALYSIS", write the report; don't wait for them
to finish their analysis. "Awaiting analysis" just means that NVD hasn't yet looked
at the vulnerability and assigned a severity score/CWE etc. Since we don't care about
those pieces of information, we can ignore that banner and just create a report if
the vulnerability is in scope for our database.
