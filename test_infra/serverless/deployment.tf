variable "serverless_project_name" {
  type        = string
  default     = ""
  description = "The Serverless project name to use"
}

variable "serverless_region_id" {
  type        = string
  default     = "aws-us-east-1"
  description = "The Serverless region to use"
}

resource "random_uuid" "project_name_suffix" {
}

locals {
  project_name = coalesce(var.serverless_project_name, join("-", [
    "elastic-agent-ci", substr(random_uuid.project_name_suffix.result, 0, 8)
  ]))
}

resource "ec_observability_project" "project" {
  name      = local.project_name
  region_id = var.serverless_region_id
}
