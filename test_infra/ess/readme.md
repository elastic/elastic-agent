## Terraform-managed Elastic Stack deployment for integration tests 

### Required variables
`stack_version` - The version of the Elastic Stack to deploy, e.g., `9.1.0-SNAPSHOT`.

### Stable snapshots and images override

Variables can be overridden to use stable snapshots or images instead of the latest snapshot. This is useful for testing against a specific version of the Elastic Stack.

* `integration_server_docker_image` - The Docker image for the integration server
* `elasticsearch_docker_image` - The Docker image for Elasticsearch
* `kibana_docker_image` - The Docker image for Kibana, e.g.

#### The priority of the docker images is as follows:
example for `integration_server_docker_image`:
1) By default, the images version will be taken from the `test_infra/ess/.stable-snapshot-version`. For example: `docker.elastic.co/cloud-release/elastic-agent-cloud:[stable-snapshot-version]`
2) Variable override: `TF_VAR_integration_server_docker_image...` takes precedence over
3) `pkg/testing/ess/create_deployment_csp_configuration.yaml` - add `docker` section to pin , e.g.:
```yaml
docker:
  integration_server_docker_image: "docker.elastic.co/cloud-release/elastic-agent-cloud:9.1.0-SNAPSHOT"
  elasticsearch_docker_image: "..."
  kibana_docker_image: "..."
```
