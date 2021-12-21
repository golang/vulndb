# worker

`worker` is a binary that can act as both a CLI and a web server.

With no command-line arguments, it listens for HTTP traffic at the `PORT`
environment variable. There is no reason to run the server locally (except
debugging), so this document describes only the CLI.

The CLI can display Firestore database of CVE records, update the database from
commits of the CVE repo github.com/CVEProject/cvelist, and file issues.

To run most CLI commands you'll need a `-project` flag, to specify the GCP
project where the Firestore DB resides. Since there is only one Firestore DB per
project and we want multiple, independent DBs, we also require a string called the
"namespace," specified with `-namespace`.

## update COMMIT

The update command takes a commit hash from the github.com/CVEProject/cvelist
repo, and modifies the DB to match the commit, creating and modifying CVE
records as needed. It does not file any issues; it only categorizes CVEs as
needing issues, not requiring action, and so on.

The command

```
worker -project go-vuln -namespace test update HEAD
```

will clone the cvelist repo from github and update the `test` namespace with the
most recent commit of the repo. It will contact pkg.go.dev to determine whether
URLs are modules.

To update at a different commit, or just to avoid the clone, clone the repo
locally and provide a path to it:

```
worker -project go-vuln -namespace test \
    -local-cve-repo ~/repos/github.com/CVEProject/cvelist \
    update cb2d8ae8ac0afed043d0fd99669e1aaac42e8b69
```

To avoid hitting pkg.go.dev, compile a file of known module paths, one per line,
and pass it as well:

```
worker -project go-vuln -namespace test \
    -local-cve-repo ~/repos/github.com/CVEProject/cvelist \
    -known-module-file ~/module-paths.txt \
    update cb2d8ae8ac0afed043d0fd99669e1aaac42e8b69
```

If an update is interrupted or fails to complete, subsequent calls to `worker
update` will fail. If you're sure there is no concurrent update in progress, it
is safe to pass the `-force` flag to force the update.

## list-cves

The command
```
worker -project go-vuln -namespace test list-cves NeedsIssue
```
will list all CVE records that need an issue. You can also use these other
argument values (from internal/worker/store/store.go:TriageState):

- IssueCreated
- UpdatedSinceIssueCreation
- HasVuln
- FalsePositive

It's not recommended to pass the "NoActionNeeded" triage state, because the vast
majority of records have this state and listing them takes a long time.

## create-issues

To create issues from records that need them, use the `create-issues` subcommand
and provide a repo and the path to a file that holds a GitHub access token.
You can also limit the number of issues created.

```
worker -project go-vuln -namespace test \
    -issue-repo myorg/myrepo \
    -ghtokenfile ~/github-token \
    -limit 10 \
    create-issues
```

## list-updates

This subcommand shows the update operations that have run, most to least recent.

## show

Run `show` with a list of CVE IDs to display the corresponding CVE records.
