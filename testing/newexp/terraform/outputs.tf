output "vm_public_address" {
  value = google_compute_instance.vm_instance.network_interface[0].access_config[0].nat_ip
}

output "ssh_user" {
  value = local.ssh_user
}

output "private_key_file" {
  value = local_sensitive_file.private_ssh_key.filename
}

output "repo_dir" {
  value = local.repo_dir
}