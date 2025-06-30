## Terraform-managed Elastic Stack deployment for integration tests

### Required variables
`stack_version` - The version of the Elastic Stack to deploy, e.g., `9.1.0-SNAPSHOT`.

### Stable snapshots and images override
This deployment uses the latest tested snapshots of the Elastic Stack components by default. However, you can override the Docker images used for the integration server, Elasticsearch, and Kibana.

`create_deployment_csp_configuration.yaml` contains the default configuration for the deployment, including the Docker images for the integration server, Elasticsearch, and Kibana. These images are automatically updated to the latest tested snapshots of the Elastic Stack components.
* `integration_server_image` - The Docker image for the integration server
* `elasticsearch_docker_image` - The Docker image for Elasticsearch
* `kibana_docker_image` - The Docker image for Kibana

Alternatively, you can override these images by setting terraform variables by setting the following variables in your local `terraform.tfvars` file:
```hcl
integration_server_docker_image = "docker.elastic.co/cloud-release/elastic-agent-cloud:9.1.0-48398db3-SNAPSHOT"
elasticsearch_docker_image = "docker.elastic.co/cloud-release/elasticsearch-cloud-ess:9.1.0-48398db3-SNAPSHOT"
kibana_docker_image = "docker.elastic.co/cloud-release/kibana-cloud:9.1.0-48398db3-SNAPSHOT"
```

or by setting the environment variables:
```bash
export TF_VAR_integration_server_docker_image="docker.elastic.co/cloud-release/elastic-agent-cloud:9.1.0-48398db3-SNAPSHOT"
export TF_VAR_elasticsearch_docker_image="docker.elastic.co/cloud-release/elasticsearch-cloud-ess:9.1.0-48398db3-SNAPSHOT"
export TF_VAR_kibana_docker_image="docker.elastic.co/cloud-release/kibana-cloud:9.1.0-48398db3-SNAPSHOT"
```

Note: terraform variables take precedence over `create_deployment_csp_configuration.yaml` docker images configuration. Use `terraform.tfvars` and `TF_VAR_` environment variables to override the images if you don't want to modify the `create_deployment_csp_configuration.yaml` file.
