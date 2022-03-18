# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Config for vuln worker.

################################################################
# Inputs.

variable "env" {
  description = "environment name"
  type        = string
}

variable "project" {
  description = "GCP project"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "use_profiler" {
  description = "use Stackdriver Profiler"
  type        = bool
}

variable "min_frontend_instances" {
  description = "minimum number of frontend instances"
  type        = number
}

variable "oauth_client_id" {
  description = "OAuth 2 client ID (visit APIs & Services > Credentials)"
  type        = string
}

variable "issue_repo" {
  description = "name of GitHub repo to post issues on"
  type        = string
}


################################################################
# Cloud Run service.

resource "google_cloud_run_service" "worker" {
  provider = google-beta

  lifecycle {
    ignore_changes = [
      # When we deploy, we may use different clients at different versions.
      # Ignore those changes.
      template[0].metadata[0].annotations["run.googleapis.com/client-name"],
      template[0].metadata[0].annotations["run.googleapis.com/client-version"]
    ]
  }

  name     = "${var.env}-vuln-worker"
  project  = var.project
  location = var.region

  template {
    spec {
      containers {
        # Get the image from GCP (see the "data" block below).
        # Exception: when first creating the service, replace this with a hardcoded
        # image tag.
        image = data.google_cloud_run_service.worker.template[0].spec[0].containers[0].image
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project
        }
        env {
          name  = "VULN_WORKER_NAMESPACE"
          value = var.env
        }
        env {
          name  = "VULN_WORKER_REPORT_ERRORS"
          value = true
        }
        env {
          name  = "VULN_WORKER_ISSUE_REPO"
          value = var.issue_repo
        }
        env {
          name = "VULN_GITHUB_ACCESS_TOKEN"
          value_from {
            secret_key_ref {
              name = google_secret_manager_secret.vuln_github_access_token.secret_id
              key  = "latest"
            }
          }
        }
        env {
          name  = "VULN_WORKER_USE_PROFILER"
          value = var.use_profiler
        }
        resources {
          limits = {
            "cpu"    = "2000m"
            "memory" = "8Gi"
          }
        }
      }

      service_account_name = data.google_compute_default_service_account.default.email
      # 60 minutes is the maximum Cloud Run request time.
      timeout_seconds = 60 * 60
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale" = var.min_frontend_instances
        "autoscaling.knative.dev/maxScale" = "1"
        #"client.knative.dev/user-image"     = data.google_cloud_run_service.worker.template[0].spec[0].containers[0].image
      }
    }
  }
  autogenerate_revision_name = true

  traffic {
    latest_revision = true
    percent         = 100
  }
}

# We deploy new images with gcloud, not terraform, so we need to
# make sure that "terraform apply" doesn't change the deployed image
# to whatever is in this file. (The image attribute is required in
# a Cloud Run config; it can't be empty.)
#
# We use this data source is used to determine the deployed image.
data "google_cloud_run_service" "worker" {
  name     = "${var.env}-vuln-worker"
  project  = var.project
  location = var.region
}

################################################################
# Other components.

locals {
  tz = "America/New_York"
}

resource "google_secret_manager_secret" "vuln_github_access_token" {
  secret_id = "vuln-${var.env}-github-access-token"
  project   = var.project
  replication {
    automatic = true
  }
}

data "google_compute_default_service_account" "default" {
  project = var.project
}

resource "google_cloud_scheduler_job" "vuln_issue_triage" {
  name             = "vuln-${var.env}-issue-triage"
  description      = "Updates the DB and files issues."
  schedule         = "0 * * * *" # every hour
  time_zone        = local.tz
  project          = var.project
  attempt_deadline = format("%ds", 30 * 60)

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_service.worker.status[0].url}/update-and-issues"
    oidc_token {
      service_account_email = data.google_compute_default_service_account.default.email
      audience              = var.oauth_client_id
    }
  }

  retry_config {
    max_backoff_duration = "3600s"
    max_doublings        = 5
    max_retry_duration   = "0s"
    min_backoff_duration = "5s"
    retry_count          = 0
  }
}

