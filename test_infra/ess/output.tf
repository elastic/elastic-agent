output "cloud_id" {
  value       = ec_deployment.integration-testing.elasticsearch.cloud_id
  description = "Cloud ID (cloud_id)"
}

output "es_password" {
  value       = ec_deployment.integration-testing.elasticsearch_password
  description = "Password (cloud_id)"
  sensitive   = true
}

output "es_username" {
  value       = ec_deployment.integration-testing.elasticsearch_username
  description = "Password (cloud_id)"
  sensitive   = true
}

output "es_host" {
  value       = ec_deployment.integration-testing.elasticsearch.https_endpoint
  description = ""
}

output "kibana_endpoint" {
  value = ec_deployment.integration-testing.kibana.https_endpoint
}

output "integrations_server_endpoint" {
  value = ec_deployment.integration-testing.integrations_server.https_endpoint
}
