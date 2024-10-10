variable "stack_version" {
  type        = string
  default     = "latest"
  description = "the stack version to use"
}

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

variable "creator" {
  type        = string
  default     = ""
  description = "This is the name who created this deployment"
}

variable "buildkite_id" {
  type        = string
  default     = ""
  description = "The buildkite build id associated with this deployment"
}

variable "pipeline" {
  type        = string
  default     = ""
  description = "The buildkite pipeline slug, useful for in combination with the build id to trace back to the pipeline"
}

resource "random_uuid" "deployment_suffix" {
}

locals {
  deployment_name    = join("-", ["elastic-agent-ci", substr("${random_uuid.deployment_suffix.result}", 0, 8)])
  deployment_version = data.ec_stack.latest.version

  ess_region             = coalesce(var.ess_region, "gcp-us-east1")
  deployment_template_id = coalesce(var.deployment_template_id, "gcp-cpu-optimized-v7")
}

# If we have defined a stack version, validate that this version exists on that region and return it.
data "ec_stack" "latest" {
  version_regex = var.stack_version
  region        = local.ess_region
}

resource "ec_deployment" "integration-testing" {
  name                   = local.deployment_name
  alias                  = local.deployment_name
  region                 = local.ess_region
  deployment_template_id = local.deployment_template_id
  version                = local.deployment_version

  elasticsearch = {
    autoscale = false

    hot = {
      autoscaling = {}
      size        = "4g"
      zone_count  = 1
    }
  }
  kibana = {
    size       = "1g"
    zone_count = 1
  }

  integrations_server = {
    topology = {
      size       = "1g"
      zone_count = 1
    }
  }

  tags = {
    "provisioner"  = "elastic-agent-integration-tests"
    "creator"      = var.creator
    "buildkite_id" = var.buildkite_id
    "pipeline"     = var.pipeline
  }
}
