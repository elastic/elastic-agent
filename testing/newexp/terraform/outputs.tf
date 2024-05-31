output "test_machine" {
  value = {
    name = google_compute_instance.ubuntu_2204_instance.name
    platform = "linux/amd64"
    public_ip = google_compute_instance.ubuntu_2204_instance.network_interface.0.access_config.0.nat_ip
    ssh_user = local.ssh_user
    ssh_key = local_sensitive_file.private_ssh_key.filename
    repo_dir = local.repo_dir
  }
}

output "ess-deployment" {
  sensitive = true
  value = {
    name = ec_deployment.integration-testing.name
    version = ec_deployment.integration-testing.version
    region = ec_deployment.integration-testing.region
    es_user = ec_deployment.integration-testing.elasticsearch_username
    es_password = ec_deployment.integration-testing.elasticsearch_password
    es_host = ec_deployment.integration-testing.elasticsearch.https_endpoint
    kibana_host = ec_deployment.integration-testing.kibana.https_endpoint
  }
}