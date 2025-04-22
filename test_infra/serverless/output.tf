output "cloud_id" {
  value       = ec_observability_project.project.cloud_id
  description = "Cloud ID (cloud_id)"
}

output "es_password" {
  value       = ec_observability_project.project.credentials.password
  description = "Password (cloud_id)"
  sensitive   = true
}

output "es_username" {
  value       = ec_observability_project.project.credentials.username
  description = "Password (cloud_id)"
  sensitive   = true
}

output "es_host" {
  value       = ec_observability_project.project.endpoints.elasticsearch
  description = "The endpoint to access elasticsearch"
}

output "kibana_endpoint" {
  value = ec_observability_project.project.endpoints.kibana
  description = "The endpoint to access kibana"
}
