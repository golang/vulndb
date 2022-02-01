# Deploy

The Go vulndb project is hosted on GCP and uses a continuous integration
service called “Kokoro” for running tests.

This directory contains files used for kokoro test job configurations and for
building and deploying the vulnerability database and worker.
(Additional job definitions live in an internal repository).

`kokoro.sh` acts as the entry point for scripts to be run via kokoro.

`build.yaml` and `gcp-deploy.sh` are used to deploy the vulnerability database
GCS bucket.

`worker.yaml` is used to build the vulnerability database worker.
