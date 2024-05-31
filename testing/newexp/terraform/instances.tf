provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
  default_labels = {
    integration-tests = "true"
    division = "engineering"
    org = "engineering"
    team = "elastic-agent-control-plane"
    project= "elastic-agent"

    build_id = var.build_id
  }
}

resource "tls_private_key" "ssh_key" {
  algorithm = "ED25519"
}

resource "local_sensitive_file" "private_ssh_key" {
  content  = tls_private_key.ssh_key.private_key_openssh
  filename = "${path.module}/.ssh/id_ed25519"
  file_permission = "0600"
  directory_permission = "0700"
}

resource "local_file" "public_ssh_key" {
  content  = tls_private_key.ssh_key.public_key_openssh
  filename = "${path.module}/.ssh/id_ed25519.pub"
  file_permission = "0600"
  directory_permission = "0700"

}

resource "google_compute_instance" "vm_instance" {
  name         = "tf-test-instance"
  machine_type = "e2-standard-2"
  lifecycle {
    ignore_changes = [metadata["ssh-keys"]]
  }
  boot_disk {
    initialize_params {
      image = "ubuntu-2204-lts"
#      image = "elastic-images-prod/platform-ingest-beats-ubuntu-2204"
    }
  }
  network_interface {
    #    network = google_compute_network.default.self_link
    #    subnetwork = google_compute_subnetwork.private_network.self_link
    network = "default"
    access_config {}
  }
  metadata = {
    "ssh-keys": <<EOF
    ${local.ssh_user}:${local_file.public_ssh_key.content}
    EOF
  }
  depends_on = [tls_private_key.ssh_key,local_file.public_ssh_key]

  connection {
    type = "ssh"
    user = local.ssh_user
    host = self.network_interface[0].access_config[0].nat_ip
    private_key = tls_private_key.ssh_key.private_key_openssh
  }


#  # The provisioner below is for elastic linux image where we have asdf but it doesn't work with non-interactive ssh commands (we need a shell)
#  provisioner "remote-exec" {
#    inline = [
#      "sudo mkdir -p ${local.repo_dir}",
#      "sudo chown ${local.ssh_user}:${local.ssh_user} ${local.repo_dir}",
#      # fix shell of the user if it's not bash to have asdf working
#      "sudo sed -i 's/\\(${local.ssh_user}:.*\\):\\/bin\\/sh/\\1:\\/bin\\/bash/g' /etc/passwd",
#      "sudo sh -c \"echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/environment\"",
#      "asdf global golang ${local.go_version}",
#    ]
#  }

    # The provisioner below is for a plain linux image where we have to install go from scratch
    provisioner "remote-exec" {
      inline = [
        "wget https://go.dev/dl/go${local.go_version}.linux-amd64.tar.gz",
        "sudo tar -C /usr/local -xzf go${local.go_version}.linux-amd64.tar.gz",
        "sudo mkdir -p ${local.repo_dir}",
        "sudo chown ${local.ssh_user}:${local.ssh_user} ${local.repo_dir}",
        #"git clone --depth 1 ${local.git_repo} ${local.repo_dir}",
        #"sudo touch /etc/profile.d/golang-path.sh && sudo chown ${local.ssh_user}:${local.ssh_user} /etc/profile.d/golang-path.sh"
        "sudo sh -c \"echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/environment\""
      ]
    }
}

# This syncs local source code with the one on the VM
resource "terraform_data" "sync_repo" {

  # trick to always provision the resource
  triggers_replace = [
    uuid()
  ]

  provisioner "local-exec" {
    command = "rsync -av -e \"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${local_sensitive_file.private_ssh_key.filename}\" --exclude-from=${data.external.golist_dump.result.Root}/.rsync.exclude --timeout=30 --delete ${data.external.golist_dump.result.Root} ${local.ssh_user}@${google_compute_instance.vm_instance.network_interface[0].access_config[0].nat_ip}:$(dirname ${local.repo_dir})"
  }
  depends_on = [
    google_compute_instance.vm_instance
  ]
}

# Network stuff

#resource "google_compute_network" "vpc_network" {
#  name                    = "tf-test-network"
#  auto_create_subnetworks = false
#  delete_default_routes_on_create = true
#}
#
#resource "google_compute_subnetwork" "private_network" {
#  name          = "tf-test-private-network"
#  ip_cidr_range = "10.2.0.0/16"
#  network       = google_compute_network.vpc_network.self_link
#}
#
#resource "google_compute_router" "router" {
#  name    = "tf-test-router"
#  network = google_compute_network.vpc_network.self_link
#}
#
#resource "google_compute_route" "private_network_internet_route" {
#  name             = "private-network-internet"
#  dest_range       = "0.0.0.0/0"
#  network          = google_compute_network.vpc_network.self_link
#  next_hop_gateway = "default-internet-gateway"
#  priority    = 100
#}
