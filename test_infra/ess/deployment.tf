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

variable "integration_server_docker_image" {
  type        = string
  default     = ""
  description = "Docker image override for integration server"
}

variable "elasticsearch_docker_image" {
  type        = string
  default     = ""
  description = "Docker image override for elasticsearch"
}

variable "kibana_docker_image" {
  type        = string
  default     = ""
  description = "Docker image override for kibana"
}

resource "random_uuid" "deployment_suffix" {
}

locals {
  deployment_name    = join("-", ["elastic-agent-ci", substr("${random_uuid.deployment_suffix.result}", 0, 8)])
  deployment_version = data.ec_stack.latest.version

  ess_region             = coalesce(var.ess_region, "gcp-us-east1")
  deployment_template_id = coalesce(var.deployment_template_id, "gcp-storage-optimized")

  ess_properties = yamldecode(file("${path.module}/../../pkg/testing/ess/create_deployment_csp_configuration.yaml"))

  integration_server_docker_image = coalesce(var.integration_server_docker_image, local.ess_properties.docker.integration_server_image)
  elasticsearch_docker_image = coalesce(var.elasticsearch_docker_image, local.ess_properties.docker.elasticsearch_image)
  kibana_docker_image = coalesce(var.kibana_docker_image, local.ess_properties.docker.kibana_image)
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
    autoscale                 = false
    hot = {
      autoscaling = {}
      size        = "8g"
      zone_count  = 1
    }
    config = {
      docker_image = local.elasticsearch_docker_image
    }
  }
  kibana = {
    size                      = "1g"
    zone_count                = 1
    config = {
      user_settings_json = jsonencode({
        "xpack.fleet.enableExperimental"                          = ["agentTamperProtectionEnabled"]
        "xpack.fleet.internal.registry.kibanaVersionCheckEnabled" = false
        "server.restrictInternalApis"                             = false
      })
      docker_image = local.kibana_docker_image
    }
  }

  integrations_server = {
    topology = {
      size       = "1g"
      zone_count = 1
    }
    config = {
      docker_image = local.integration_server_docker_image
    }
  }

  tags = {
    "provisioner"  = "elastic-agent-integration-tests"
    "creator"      = var.creator
    "buildkite_id" = var.buildkite_id
    "pipeline"     = var.pipeline
  }
}
