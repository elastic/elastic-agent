---
cluster_name: "{{ .ClusterName }}"
template_name: "elastic-agent-e2e"
create_users: false
grab_cluster_info: false
create_ilm: false
certificate_issuer: letsencrypt-staging
slack_channel: "{{ .SlackChannel }}"
digest_secrets_enabled: true
secret_ec_user: "observability-team/ci/elastic-cloud/observability-pro"

elastic_cloud:
  provider: gcp
  region: gcp-us-west2
  endpoint: https://cloud.elastic.co
  zones: 1
  template: gcp-io-optimized-v2

elasticsearch:
  enabled: true
  version: "{{ .StackVersion }}"
  type: tf

kibana:
  version: "{{ .StackVersion }}"
  enabled: true
  type: tf
  mem: 1
  apm_enabled: false

apm:
  enabled: true
  version: "{{ .StackVersion }}"
  image: "docker.elastic.co/observability-ci/elastic-agent-cloud:{{ .StackVersion }}"
  type: tf
  mem: 2

k8s:
  enabled: false
