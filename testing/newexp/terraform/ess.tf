locals {
  # FIXME
  deployment_name    = join("-", ["elastic-agent-integration-tests", "aaaaa"])
  # FIXME
  deployment_version = "8.15.0-SNAPSHOT"

  ess_region             = coalesce(var.ess_region, "gcp-us-west2")
  deployment_template_id = coalesce(var.deployment_template_id, "gcp-cpu-optimized-v7")
}



provider "ec" {
  # FIXME
  apikey = file("~/.config/ess/api_key.txt")
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
      size        = "8g"
      zone_count  = 1
    }
  }
  kibana = {
    size       = "1g"
    zone_count = 1
  }

  integrations_server = {
    size = "1g"
    zone_count = 1
  }

  tags = {
    "provisioner"    = "elastic-agent-integration-test"
    #"environment_id" = var.environment_id
    #"creator"        = var.creator
    "buildkite_id"   = var.build_id
  }
}