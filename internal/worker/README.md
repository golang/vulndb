# Go Vulnerability Worker

The vuln worker triages incoming security advisories and scans selected modules
for vulnerabilities.

The Go security team runs the worker on Google Cloud Platform's Cloud Run
product. See the repo's `terraform` directory for more on the deployment setup.

The main program for the worker, in the repo's `cmd/worker` directory, can also
be used as a command-line tool for one-off executions of some of the server's
actions.

## Browsing the worker

Accessing the worker server's home page from a browser requires authentication.
We recommend
[cloud-run-proxy](https://github.com/GoogleCloudPlatform/cloud-run-proxy) for
painless browsing. Install it with
```
go install github.com/GoogleCloudPlatform/cloud-run-proxy@latest
```

Run it from the repo root with
```
./devtools/proxy_worker.sh prod
```
