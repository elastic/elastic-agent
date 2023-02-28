terraform {
  required_version = ">= 1.1.8, < 2.0.0"
  required_providers {
    ec = {
      source  = "elastic/ec"
      version = ">=0.4.0"
    }
  }
}

provider "ec" {}

locals {
  match            = regex("const defaultBeatVersion = \"(.*)\"", file("${path.module}/../../../version/version.go"))[0]
  stack_version    = format("%s-SNAPSHOT", local.match) 
}

module "ec_deployment" {
  source = "../infra/terraform/modules/ec_deployment"

  region        = var.ess_region
  stack_version = local.stack_version

  deployment_template    = var.deployment_template
  deployment_name_prefix = "elastic-agent-server-testing"

  apm_server_size       = var.apm_server_size
  apm_server_zone_count = var.apm_server_zone_count

  elasticsearch_size       = var.elasticsearch_size
  elasticsearch_zone_count = var.elasticsearch_zone_count

  docker_image = var.docker_image_override
  docker_image_tag_override = {
    "elasticsearch" : coalesce(var.docker_image_tag_override["elasticsearch"], local.stack_version),
    "kibana" : coalesce(var.docker_image_tag_override["kibana"], local.stack_version),
    "agent" : coalesce(var.docker_image_tag_override["agent"], local.stack_version)
  }
}
