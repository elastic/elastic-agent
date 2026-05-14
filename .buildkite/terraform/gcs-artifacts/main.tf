# Terraform module for Buildkite GCS Artifacts with OIDC
# This automates the setup of Google Cloud Storage for Buildkite artifacts
# with Workload Identity Federation (OIDC) authentication

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "bucket_name" {
  description = "GCS bucket name for artifacts"
  type        = string
  default     = "bk-elastic-agent"
}

variable "bucket_location" {
  description = "GCS bucket location"
  type        = string
  default     = "US"
}

variable "buildkite_organization_slug" {
  description = "Buildkite organization slug (e.g., 'elastic')"
  type        = string
  default     = "elastic"
}

variable "allowed_pipeline_slugs" {
  description = "List of allowed pipeline slugs (empty = all pipelines in org)"
  type        = list(string)
  default     = []
}

variable "artifact_retention_days" {
  description = "Days to retain artifacts before deletion"
  type        = number
  default     = 30
}

variable "test_artifact_retention_days" {
  description = "Days to retain test/PR artifacts"
  type        = number
  default     = 7
}

variable "elastic_users_group" {
  description = "Google Group email for Elastic users with read access"
  type        = string
  default     = "buildkite-users@elastic.co"
}

# Data sources
data "google_project" "project" {
  project_id = var.project_id
}

# GCS Bucket
resource "google_storage_bucket" "artifacts" {
  name          = var.bucket_name
  project       = var.project_id
  location      = var.bucket_location
  storage_class = "STANDARD"

  # Block public access
  public_access_prevention = "enforced"

  # Uniform bucket-level access (recommended)
  uniform_bucket_level_access {
    enabled = true
  }

  # Versioning disabled to save costs
  versioning {
    enabled = false
  }

  # Lifecycle rules for automatic cleanup
  lifecycle_rule {
    condition {
      age = var.artifact_retention_days
      matches_prefix = [
        "${var.buildkite_organization_slug}/",
      ]
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      age = var.test_artifact_retention_days
      matches_prefix = [
        "${var.buildkite_organization_slug}/*/pr/",
        "${var.buildkite_organization_slug}/*/test/",
      ]
    }
    action {
      type = "Delete"
    }
  }

  # Optional: Transition to Nearline after 7 days
  lifecycle_rule {
    condition {
      age           = 7
      matches_prefix = ["${var.buildkite_organization_slug}/"]
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  labels = {
    managed_by = "terraform"
    purpose    = "buildkite-artifacts"
    team       = "elastic-agent"
  }
}

# Workload Identity Pool
resource "google_iam_workload_identity_pool" "buildkite" {
  project                   = var.project_id
  workload_identity_pool_id = "buildkite-artifacts-pool"
  display_name              = "Buildkite Artifacts OIDC Pool"
  description               = "Workload Identity Pool for Buildkite agents to access GCS artifacts"
}

# OIDC Provider in the Pool
resource "google_iam_workload_identity_pool_provider" "buildkite_oidc" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.buildkite.workload_identity_pool_id
  workload_identity_pool_provider_id = "buildkite-oidc-provider"
  display_name                       = "Buildkite OIDC Provider"
  description                        = "OIDC provider for Buildkite agent authentication"

  # Buildkite OIDC configuration
  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.organization_slug" = "assertion.organization_slug"
    "attribute.pipeline_slug"     = "assertion.pipeline_slug"
    "attribute.build_branch"      = "assertion.build_branch"
    "attribute.build_number"      = "assertion.build_number"
    "attribute.job_id"            = "assertion.job_id"
  }

  # Restrict to specific Buildkite organization
  attribute_condition = "assertion.organization_slug == '${var.buildkite_organization_slug}'"

  oidc {
    issuer_uri = "https://agent.buildkite.com"
    # Audience is automatically set to the provider resource name
    allowed_audiences = []
  }
}

# Service Account for Buildkite
resource "google_service_account" "buildkite_artifacts" {
  project      = var.project_id
  account_id   = "buildkite-artifacts-sa"
  display_name = "Buildkite Artifacts Service Account"
  description  = "Service account for Buildkite agents to upload/download artifacts from GCS"
}

# Grant Storage Object Admin to the service account on the bucket
resource "google_storage_bucket_iam_member" "buildkite_sa_object_admin" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.buildkite_artifacts.email}"
}

# Allow Workload Identity Pool to impersonate the service account
# This binding allows ANY pipeline in the organization to use the service account
resource "google_service_account_iam_member" "workload_identity_user_org" {
  count              = length(var.allowed_pipeline_slugs) == 0 ? 1 : 0
  service_account_id = google_service_account.buildkite_artifacts.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.buildkite.name}/attribute.organization_slug/${var.buildkite_organization_slug}"
}

# Alternative: Restrict to specific pipelines
resource "google_service_account_iam_member" "workload_identity_user_pipelines" {
  for_each           = toset(var.allowed_pipeline_slugs)
  service_account_id = google_service_account.buildkite_artifacts.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.buildkite.name}/attribute.pipeline_slug/${each.value}"
}

# Grant Elastic users read access to artifacts
resource "google_storage_bucket_iam_member" "elastic_users_viewer" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectViewer"
  member = "group:${var.elastic_users_group}"
}

# Outputs
output "bucket_name" {
  description = "GCS bucket name"
  value       = google_storage_bucket.artifacts.name
}

output "bucket_url" {
  description = "GCS bucket URL"
  value       = google_storage_bucket.artifacts.url
}

output "service_account_email" {
  description = "Service account email for Buildkite agents"
  value       = google_service_account.buildkite_artifacts.email
}

output "workload_identity_provider" {
  description = "Workload Identity Provider resource name (use as audience in Buildkite plugin)"
  value       = google_iam_workload_identity_pool_provider.buildkite_oidc.name
}

output "plugin_audience" {
  description = "Audience parameter for gcp-workload-identity-federation plugin (without https:// prefix)"
  value       = trimsuffix(trimprefix(google_iam_workload_identity_pool_provider.buildkite_oidc.name, "//iam.googleapis.com/"), "")
}

output "buildkite_environment_hook" {
  description = "Environment hook configuration for Buildkite agents"
  value       = <<-EOT
    #!/bin/bash
    # Add this to .buildkite/hooks/environment
    export BUILDKITE_ARTIFACT_UPLOAD_DESTINATION="gs://${google_storage_bucket.artifacts.name}/$${BUILDKITE_ORGANIZATION_SLUG}/$${BUILDKITE_PIPELINE_SLUG}/$${BUILDKITE_BUILD_NUMBER}"
    export BUILDKITE_GS_ACL="private"
    export BUILDKITE_GCS_ACCESS_HOST="storage.cloud.google.com"
  EOT
}

output "buildkite_plugin_config" {
  description = "Plugin configuration for pipeline YAML"
  value       = <<-EOT
    # Add this to your pipeline steps:
    plugins:
      - gcp-workload-identity-federation#v1.5.0:
          audience: "${trimsuffix(trimprefix(google_iam_workload_identity_pool_provider.buildkite_oidc.name, "//iam.googleapis.com/"), "")}"
          service-account: "${google_service_account.buildkite_artifacts.email}"
          claims:
            - organization_id
            - pipeline_id
  EOT
}
