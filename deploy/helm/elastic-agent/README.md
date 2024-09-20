<!--
(NOTE: Do not edit README.md directly. It is a generated file!)
(      To make changes, please modify README.md.gotmpl and run `helm-docs`)
-->

# elastic-agent

![Version: 0.0.1](https://img.shields.io/badge/Version-0.0.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square)

Elastic-Agent Helm Chart

This chart simplifies the deployment of Elastic Agent in Kubernetes and features a built-in Kubernetes policy.

## Values

### 1 - Outputs
The outputs section specifies where to send data. You can specify multiple outputs to pair specific inputs with specific outputs.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| outputs | map[string][OutputObject](#11---output-object) | `{ "default" : {} }` | The key of the map is the name of the output and the value is an object containing the fields below |

### 1.1 - Output Object
The supported types of outputs are:
- `ESPlainAuthBasic`: `elasticsearch` output with the connection details (url, username, password) specified inline the yaml
- `ESPlainAuthAPI`: `elasticsearch` output with the connection details (url, api_key) specified inline the yaml
- `ESSecretAuthBasic`: `elasticsearch` output with the connection details specified in a k8s secret
- `ESSecretAuthAPI`: `elasticsearch` output with the connection details specified in a k8s secret
- `ESECKRef`: `elasticsearch` output that references by name an Elasticsearch cluster managed by ECK operator

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| outputs.{name}.type | string | `"ESPlainAuthBasic"` | type of the output [one of `ESPlainAuthBasic`, `ESPlainAuthAPI`, `ESSecretAuthBasic`, `ESSecretAuthAPI`, `ESECKRef`] |
| outputs.{name}.url | string | `""` | url of the output [required for types `ESPlainAuthBasic` and `ESPlainAuthAPI`] |
| outputs.{name}.username | string | `""` | the username to use to authenticate with the output [required for type `ESPlainAuthBasic`] |
| outputs.{name}.password | string | `""` | the password to use to authenticate with the output [required for type `ESPlainAuthBasic`] |
| outputs.{name}.api_key | string | `""` | the API key use to authenticate with the output [required for type `ESPlainAuthAPI`] |
| outputs.{name}.secretName | string | `""` | the k8s secret to mount output connection details [required for types `ESSecretAuthBasic` and `ESSecretAuthAPI`] |
| outputs.{name}.name | string | `""` | name to reference an Elasticsearch cluster managed by ECK [required for type `ESECKRef`] |
| outputs.{name}.namespace | string | `""` | namespace to reference an Elasticsearch cluster managed by ECK [optional for type `ESECKRef`] |
Examples of Helm chart arguments to define an output with name `myOutput`:
- `ESPlainAuthBasic`: `--set outputs.myOutput.url=https://elasticsearch:9200 --set outputs.myOutput.username=changeme --set outputs.myOutput.password=changeme`
- `ESPlainAuthAPI`: `--set outputs.myOutput.url=https://elasticsearch:9200 --set outputs.myOutput.api_key=token`
- `ESSecretAuthBasic`: `--set outputs.myOutput.type=ESSecretAuthBasic --set outputs.myOutput.secretName=k8s_secret_name` (required keys in the k8s secret are `url`, `username`, `password`)
- `ESSecretAuthAPI`: `--set outputs.myOutput.type=ESSecretAuthAPI --set outputs.myOutput.secretName=k8s_secret_name` (required keys in the k8s secret are `url`, `api_key`)
- `ESECKRef`: `--set outputs.myOutput.type=ESECKRef --set outputs.myOutput.name=eck_es_cluster_name`

For `ESPlainAuthBasic`, `ESPlainAuthAPI` `ESSecretAuthBasic`, `ESSecretAuthAPI` extra fields can be specified inline the yaml following these guidelines (`ESECKRef` doesn't support them):
 - ["Data parsing, filtering, and manipulation settings"](`https://www.elastic.co/guide/en/fleet/current/elasticsearch-output.html#output-elasticsearch-data-parsing-settings`)
 - ["Performance tuning settings"](https://www.elastic.co/guide/en/fleet/current/elasticsearch-output.html#output-elasticsearch-performance-tuning-settings)
 - ["Memory queue settings"](https://www.elastic.co/guide/en/fleet/current/elasticsearch-output.html#output-elasticsearch-memory-queue-settings)

### 2 - Kubernetes integration

The chart built-in [kubernetes integration](https://docs.elastic.co/integrations/kubernetes) is used to collect logs and metrics from [Kubernetes clusters](https://kubernetes.io/). This integration is capable of fetching metrics from several components:
- [kubelet](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)
- [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics)
- [apiserver](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [controller-manager](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [scheduler](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)
- [proxy](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| kubernetes.enabled | bool | `false` | enable Kubernetes integration. |
| kubernetes.output | string | `"default"` | name of the output used in kubernetes integration. Note that this output needs to be defined in [outputs](#1-outputs) |
| kubernetes.namespace | string | `"default"` | kubernetes namespace |
| kubernetes.hints.enabled | bool | `false` | enable [elastic-agent autodiscovery](https://www.elastic.co/guide/en/fleet/current/elastic-agent-kubernetes-autodiscovery.html) feature |
| kubernetes.state.enabled | bool | `true` | integration global switch to enable state streams based on kube-state-metrics. Note that setting this to `false` results in overriding and *disabling all* the respective state streams |
| kubernetes.state.deployKSM | bool | `true` | deploy kube-state-metrics service as a sidecar container to the elastic agent of `ksmShared` preset. If set to `false`, kube-state-metrics will *not* get deployed and `clusterWide` agent preset will be used for collecting kube-state-metrics. |
| kubernetes.state.host | string | `"kube-state-metrics:8080"` | host of the kube-state-metrics service. Note that this used only when `deployKSM` is set to `false`. |
| kubernetes.state.vars | object | `{}` | state streams variables such as `add_metadata`, `hosts`, `period`, `bearer_token_file`. Please note that colliding vars also defined in respective state streams will *not* be overridden. |
| kubernetes.metrics.enabled | bool | `true` | integration global switch to enable metric streams based on kubelet. Note that setting this to false results in overriding and *disabling all* the respective metric streams |
| kubernetes.metrics.vars | object | `{}` | metric streams variables such as `add_metadata`, `hosts`, `period`, `bearer_token_file`, `ssl.verification_mode`. Please note that colliding vars also defined in respective metric streams will *not* be overridden. |
| kubernetes.apiserver.enabled | bool | `true` | enable [apiserver](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-kubernetes.html#_apiserver) input |
| kubernetes.apiserver.vars | object | `{}` | apiserver variables such as  `hosts`, `period`, `bearer_token_file`, `ssl.certificate_authorities`. |
| kubernetes.proxy.enabled | bool | `false` | enable [proxy](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-kubernetes.html#_proxy) input |
| kubernetes.proxy.vars | object | `{}` | proxy stream variables such as `hosts`, `period`. |
| kubernetes.scheduler.enabled | bool | `false` | enable [scheduler](https://www.elastic.co/guide/en/beats/metricbeat/8.11/metricbeat-module-kubernetes.html#_scheduler_and_controllermanager) input |
| kubernetes.scheduler.vars | object | `{}` | scheduler stream variables such as `hosts`, `period`, `bearer_token_file`, `ssl.verification_mode`, `condition`. |
| kubernetes.controller_manager.enabled | bool | `false` | enable [controller_manager](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-kubernetes.html#_scheduler_and_controllermanager) input |
| kubernetes.controller_manager.vars | object | `{}` | controller_manager stream variables such as `hosts`, `period`, `bearer_token_file`, `ssl.verification_mode`, `condition`. |
| kubernetes.containers.metrics.enabled | bool | `true` | enable containers metric stream (kubelet) [ref](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-kubernetes-container.html) |
| kubernetes.containers.metrics.vars | object | `{}` | containers metric stream vars |
| kubernetes.containers.state.enabled | bool | `true` | enable containers state stream (kube-state-metrics) [ref](https://www.elastic.co/guide/en/beats/metricbeat/8.11/metricbeat-metricset-kubernetes-state_container.html) |
| kubernetes.containers.state.vars | object | `{}` | containers state stream vars |
| kubernetes.containers.logs.enabled | bool | `true` | enable containers logs stream [ref](https://www.elastic.co/docs/current/integrations/kubernetes/container-logs) |
| kubernetes.containers.audit_logs.enabled | bool | `false` | enable containers audit logs stream [ref](https://www.elastic.co/docs/current/integrations/kubernetes/audit-logs) |
| kubernetes.pods.metrics.enabled | bool | `true` | enable pods metric stream (kubelet) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kubelet#pod) |
| kubernetes.pods.metrics.vars | object | `{}` | pod metric stream vars |
| kubernetes.pods.state.enabled | bool | `true` | enable pods state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_pod) |
| kubernetes.pods.state.vars | object | `{}` | pods state stream vars |
| kubernetes.deployments.state.enabled | bool | `true` | enable deployments state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_deployment) |
| kubernetes.deployments.state.vars | object | `{}` | deployments state stream vars |
| kubernetes.statefulsets.state.enabled | bool | `true` | enable statefulsets state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_statefulset) |
| kubernetes.statefulsets.state.vars | object | `{}` | statefulsets state stream vars |
| kubernetes.daemonsets.state.enabled | bool | `true` | enable daemonsets state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_daemonset) |
| kubernetes.daemonsets.state.vars | object | `{}` | daemonsets state stream vars |
| kubernetes.replicasets.state.enabled | bool | `true` | enable replicasets state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_replicaset) |
| kubernetes.replicasets.state.vars | object | `{}` | replicasets state stream vars |
| kubernetes.namespaces.state.enabled | bool | `true` | enable namespaces state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_namespace) |
| kubernetes.namespaces.state.vars | object | `{}` | namespaces state stream vars |
| kubernetes.volumes.metrics.enabled | bool | `true` | enable volumes metric stream (kubelet) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kubelet#volume) |
| kubernetes.volumes.metrics.vars | object | `{}` | volumes metric stream vars |
| kubernetes.nodes.metrics.enabled | bool | `true` | enable nodes metric stream (kubelet) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kubelet#node) |
| kubernetes.nodes.metrics.vars | object | `{}` | nodes metric stream vars |
| kubernetes.nodes.state.enabled | bool | `true` | enable nodes state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#node) |
| kubernetes.nodes.state.vars | object | `{}` | nodes state stream vars |
| kubernetes.storageclasses.state.enabled | bool | `true` | enable storageclasses state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_storageclass) |
| kubernetes.storageclasses.state.vars | object | `{}` | storageclasses state stream vars |
| kubernetes.jobs.state.enabled | bool | `true` | enable jobs state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_job) |
| kubernetes.jobs.state.vars | object | `{}` | jobs state stream vars |
| kubernetes.cronjobs.state.enabled | bool | `true` | enable cronjobs state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_cronjob) |
| kubernetes.cronjobs.state.vars | object | `{}` | cronjobs state stream vars |
| kubernetes.persistentvolumes.state.enabled | bool | `true` | enable persistentvolumes state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_persistentvolume) |
| kubernetes.persistentvolumes.state.vars | object | `{}` | persistentvolumes state stream vars |
| kubernetes.persistentvolumeclaims.state.enabled | bool | `true` | enable persistentvolumeclaims state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_persistentvolumeclaim) |
| kubernetes.persistentvolumeclaims.state.vars | object | `{}` | persistentvolumeclaims state stream vars |
| kubernetes.resourcequotas.state.enabled | bool | `true` | enable resourcequotas state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_resourcequota) |
| kubernetes.resourcequotas.state.vars | object | `{}` | resourcequotas state stream vars |
| kubernetes.services.state.enabled | bool | `true` | enable services state stream (kube-state-metrics) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kube-state-metrics#state_service) |
| kubernetes.services.state.vars | object | `{}` | services state stream vars |
| kubernetes.system.metrics.enabled | bool | `true` | enable system metric stream (kubelet) [ref](https://www.elastic.co/docs/current/integrations/kubernetes/kubelet#system) |
| kubernetes.system.metrics.vars | object | `{}` | system metric stream vars |

### 3 - User Extra Integrations
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| extraIntegrations | object | `{}` | extra [user-defined integrations](https://www.elastic.co/guide/en/fleet/current/elastic-agent-input-configuration.html) to be added to the Elastic Agent An example can be found [here](./examples/nginx-custom-integration/README.md) |

### 3 - Elastic-Agent Configuration
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent.version | string | `"9.0.0"` | elastic-agent version |
| agent.image | object | `{"pullPolicy":"IfNotPresent","repository":"docker.elastic.co/beats/elastic-agent","tag":"9.0.0-SNAPSHOT"}` | image configuration |
| agent.engine | string | `"k8s"` | generate kubernetes manifests or [ECK](https://github.com/elastic/cloud-on-k8s) CRDs |
| agent.unprivileged | bool | `false` | enable unprivileged mode |
| agent.presets | map[string]{} | `{ "perNode" : {...}, "clusterWider": {...}, "ksmShared": {...} }` | Map of deployment presets for the Elastic Agent. The key of the map is the name of the preset. See more for the presets required by the built-in Kubernetes integration [here](./values.yaml) |

### 3.1 - Elastic-Agent Managed Configuration
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent.fleet.enabled | bool | `false` | enable elastic-agent managed |
| agent.fleet.url | string | `""` | Fleet server URL |
| agent.fleet.token | string | `""` | Fleet enrollment token |
| agent.fleet.insecure | bool | `false` | Fleet insecure url |
| agent.fleet.kibanaHost | string | `""` | Kibana host to fallback if enrollment token is not supplied |
| agent.fleet.kibanaUser | string | `""` | Kibana username to fallback if enrollment token is not supplied |
| agent.fleet.kibanaPassword | string | `""` | Kibana password to fallback if enrollment token is not supplied |
| agent.fleet.preset | string | `"perNode"` | Agent preset to deploy |

