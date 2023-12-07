locals {
  go_version = trimspace(file("${path.module}/../../../../.go-version"))
  ssh_user = "paolo_chila"
}

resource "random_uuid" "test_run_id" {
}

variable "project_id" {
  type        = string
  description = "The GCP project where the VMs will be created"
  default = "elastic-platform-ingest"
}
variable "region" {
  type        = string
  description = "The GCP region where the VMs will be created"
  default = "us-central1"
}
variable "zone" {
  type        = string
  description = "The GCP zone where the VMs will be created"
  default = "us-central1-a"
}

data "external" "golist_dump" {
  program = [
    "go", "list", "-json=Root", "github.com/elastic/elastic-agent"
  ]
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
  default_labels = {
    team = "elastic-agent"
    integration-tests = "true"
    run_id = random_uuid.test_run_id.id
  }
}

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


resource "tls_private_key" "ssh_key" {
  algorithm = "ED25519"
}

output "private_key" {
  value = tls_private_key.ssh_key.private_key_openssh
  sensitive=true
}

output "public_key" {
  value = tls_private_key.ssh_key.public_key_openssh
  sensitive=true
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
  boot_disk {
    initialize_params {
      image = "ubuntu-2204-lts"
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

  provisioner "remote-exec" {
    inline = [
      "wget https://go.dev/dl/go${local.go_version}.linux-amd64.tar.gz",
      "sudo tar -C /usr/local -xzf go${local.go_version}.linux-amd64.tar.gz",
      "sudo mkdir -p /src/elastic-agent",
      "sudo chown ${local.ssh_user}:${local.ssh_user} /src/elastic-agent"
    ]
  }

  provisioner "file" {
    source = data.external.golist_dump.result.Root
    destination = "/src/elastic-agent"
  }
}

output "vm_address" {
  value = google_compute_instance.vm_instance
  sensitive = true
}