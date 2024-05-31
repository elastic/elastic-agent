# VM variables
variable "project_id" {
  type        = string
  description = "The GCP project where the VMs will be created"
  default = "elastic-platform-ingest"
}
variable "region" {
  type        = string
  description = "The GCP region where the VMs will be created"
  default = "us-central1"
}
variable "zone" {
  type        = string
  description = "The GCP zone where the VMs will be created"
  default = "us-central1-a"
}

variable "build_id" {
  type        = string
  description = "Build id associated with this run"
  default = "nobuildid"
}

# ESS variables
variable "ess_region" {
  type        = string
  default     = ""
  description = "The ESS region to use"
}

variable "deployment_template_id" {
  type        = string
  default     = ""
  description = "The ess deployment template to use"
}