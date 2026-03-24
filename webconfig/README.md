# Go Vulnerability Database Web Configuration

These files control what users see when they visit [vuln.go.dev](https://vuln.go.dev), and
when they get a 404 on that site.

## Deployment

Every time a new CL is submitted, the existing `.html` and `.ico` files in this folder
are automatically copied to the vuln DB bucket via the script in
`deploy/gcp-deploy.sh`.

**If a new file is added**, update the script in `deploy/gcp-deploy.sh` and below.

### Manual deployment

In exceptional cases, the files may need to be manually copied into the bucket.
To do this, run this script:

```sh
gcloud storage cp webconfig/index.html gs://go-vulndb
for file in 404 copyright privacy; do
    gcloud storage cp webconfig/$file.html gs://go-vulndb/$file --content-type="text/html"
done
gcloud storage cp webconfig/favicon.ico gs://go-vulndb
```

This requires `golang-vulndb-project-owners` rights, which must be requested
and approved via Access on Demand (go/get-aod).

## Initial Setup

The initial setup has already been completed and no further action is required.

The go-vulndb bucket was configured to display these pages via:

```sh
gcloud storage buckets update gs://go-vulndb --web-main-page-suffix=index.html --web-error-page=404
```

Use `gcloud storage buckets describe gs://go-vulndb --format="default(website)"` to display the current configuration.
