# Terraform configuration for vuln worker

## External variables

Some inputs to this config are not checked into the repo.
You can provide them on the `terraform` command line,
or create a `terraform.tfvars` file in this directory
with the information, like this one:

```
prod_project    = "prod-project"
prod_issue_repo = "org/repo"
prod_client_id  = "xyzzy@apps.googleusercontent.com"
```

`terraform.tfvars` is in the repo's `.gitignore` file, so it won't show up in
`git status`. **Do not** check it into the repo.

## Cloud Run image

We use terraform to set up the Cloud Run service, but we deploy in other ways.
Our deploy process changes only the Docker image for the service. If we
hardcoded a Docker image into the config, our config would often be out of date
(since we apply it rarely compared to deploying), and we would risk overwriting
a newer image with the old one in the config.

For that reason, the Docker image in the config is obtained from the service
itself, by using a `data` block:

```
resource "google_cloud_run_service" "worker" {
  ...
  template {
    spec {
      containers {
        image = data.google_cloud_run_service.worker.template[0].spec[0].containers[0].image
  ...
}

data "google_cloud_run_service" "worker" {
  name     = "${var.env}-vuln-worker"
  project  = var.project
  location = var.region
}
```

This works fine once the service exists, but before it does we have a circularity:
to create the service we need to get the image from the service!

So to create the service:

1. Build and push a Docker image.
2. Replace the `data.google_cloud_run_service.worker` expressions (there are
   two) with the actual image label.
3. Run `terraform apply`.
4. Undo the replacement.
