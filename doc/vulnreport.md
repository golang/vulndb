# `vulnreport` command reference

[WORK IN PROGRESS]

Other useful docs:
 - [Quickstart](quickstart.md)
 - [Triage](triage.md)
 - [Report format reference](format.md)

## `vulnreport triage`

Standard usage:

```bash
$ vulnreport triage
```

This command looks at all untriaged issues to find and label:

* High-priority issues (label: `high priority`) - issues that affect modules with >= 100 importers
* Possible duplicates (label: `duplicate`) - issues
that may be duplicates of another issue because they share a CVE/GHSA
* Possibly not Go (label: `possibly Not Go`) - issues that possibly do not affect Go at all. This is applied to modules
for which more than 20% of current reports are marked `excluded: NOT_GO_CODE`.

Arguments:

The `vulnreport triage` command also accepts arguments,
e.g. `vulnreport triage 123` to triage issue #123, but the duplicate search only works properly when applied to all open issues.

Flags:

* `-dry`: don't apply labels to issues
* `-f`: force re-triage of issues labeled `triaged`