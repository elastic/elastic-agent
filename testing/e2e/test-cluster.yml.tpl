---
template_name: "elastic-agent-e2e"
template_description: |
  elastic-agent-e2e is a template for deploying ESS cluster with elastic-agent on a specific version.
  Parameters:
    - ClusterName: Name for the new oblt cluster (automatic).
    - SlackChannel: SlackChannel name or Slack member ID to send the credentials of the cluster (#my-channel, @MIDNUM)(automatic)
    - StackVersion: Elastic Stack Pack version to be use on ESS (required).
    - ElasticAgentDockerImage: Docker image to use for Elastic Agent (Optional).
    - StackBuild: Elastic Stack build version used for the Elastic Agent Docker image (optional).
  Usage:
    oblt-cli cluster create custom --template elastic-agent-e2e --parameters '{"StackVersion": "8.7.1"}'
    oblt-cli cluster create custom --template elastic-agent-e2e --parameters '{"StackVersion":"8.7.1", "ElasticAgentDockerImage": "docker.elastic.co/observability-ci/elastic-agent-cloud:8.7.1-08adc761"}'


#{{ $elasticAgentDockerImage := (printf "%s:%s" "docker.elastic.co/observability-ci/elastic-agent-cloud" .StackVersion) }}
#{{- if .ElasticAgentDockerImage }}
#{{ $elasticAgentDockerImage = .ElasticAgentDockerImage }}
#{{- end }}

cluster_name: "{{ .ClusterName }}"
slack_channel: "{{ .SlackChannel }}"
digest_secrets_enabled: true

stack:
  mode: ess
  template: observability
  version: "{{ .StackVersion }}"
  observability: true
  ess:
    integrations:
      image: "{{ $elasticAgentDockerImage }}"
