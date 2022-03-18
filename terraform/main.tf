# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Terraform configuration for GCP components from this repo.

terraform {
  required_version = ">= 1.0.9, < 2.0.0"
  # Store terraform state in a GCS bucket, so all team members share it.
  backend "gcs" {
    bucket = "go-discovery-exp"
    prefix = "vuln"
  }
  required_providers {
    google = {
      version = "~> 3.90.1"
      source  = "hashicorp/google"
    }
  }
}

locals {
  region = "us-central1"
}

provider "google" {
  region = local.region
}

# Inputs for values that should not appear in the repo.
# Terraform will prompt for these when you run it, or
# you can put them in a local file that is only readable
# by you, and pass them to terraform.
# See https://www.terraform.io/docs/language/values/variables.html#variable-definitions-tfvars-files.


variable "prod_project" {
  description = "GCP project where resources live"
  type        = string
}

variable "prod_issue_repo" {
  description = "repo where issues are filed"
  type        = string
}

variable "prod_client_id" {
  description = "OAuth2 client ID"
  type        = string
}

variable "dev_project" {
  description = "GCP project where resources live"
  type        = string
}

variable "dev_issue_repo" {
  description = "repo where issues are filed"
  type        = string
}

variable "dev_client_id" {
  description = "OAuth2 client ID"
  type        = string
}

# Deployment environments

module "dev" {
  source                 = "./environment"
  env                    = "dev"
  project                = var.dev_project
  region                 = local.region
  use_profiler           = false
  min_frontend_instances = 0
  oauth_client_id        = var.dev_client_id
  issue_repo             = var.dev_issue_repo
}

module "prod" {
  source                 = "./environment"
  env                    = "prod"
  project                = var.prod_project
  region                 = local.region
  use_profiler           = true
  min_frontend_instances = 1
  oauth_client_id        = var.prod_client_id
  issue_repo             = var.prod_issue_repo
}


resource "google_cloudbuild_trigger" "vulndb-redeploy" {
  project     = var.prod_project
  description = "Rebuild vulndb database and push to GCS bucket"
  filename    = "deploy/build.yaml"
  name        = "vulndb-redeploy"
  trigger_template {
    branch_name = "^master$"
    project_id  = "go-vuln"
    repo_name   = "vulndb"
  }
}
