## 9.0.0 [elastic-agent-9.0.0-release-notes]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.0.0-breaking-changes)._

### Features and enhancements [elastic-agent-9.0.0-features-enhancements]

* Adds the Azure Asset Inventory definition to Cloudbeat for {{agent}} [#5323]({{agent-pull}}5323)
* Adds Kubernetes deployment of the Elastic Distribution of OTel Collector named "gateway" to the Helm kube-stack deployment for {{agent}} [#6444]({{agent-pull}}6444)
* Adds the filesource provider to composable inputs. The provider watches for changes of the files and updates the values of the variables when the content of the file changes for {{agent}} [#6587]({{agent-pull}}6587) and [#6362]({{agent-issue}}6362)
* Adds the jmxreceiver to the Elastic Distribution of OTel Collector for {{agent}} [#6601]({{agent-pull}}6601)
* Adds support for context variables in outputs as well as a default provider prefix for {{agent}} [#6602]({{agent-pull}}6602) and [#6376]({{agent-issue}}6376)
* Adds the Nginx receiver and Redis receiver OTel components for {{agent}} [#6627]({{agent-pull}}6627)
* Adds --id (ELASTIC_AGENT_ID environment variable for container) and --replace-token (FLEET_REPLACE_TOKEN environment variable for container) enrollment options for {{agent}} [#6498]({{agent-pull}}6498)
* Updates Go version to 1.22.10 in {{agent}} [#6236]({{agent-pull}}6236)
* Adds the Filebeat receiver into {{agent}} [#5833]({{agent-pull}}5833)
* Updates OTel components to v0.119.0 in {{agent}} [#6713]({{agent-pull}}6713)

### Fixes [elastic-agent-9.0.0-fixes]

* Fixes logical race conditions in the kubernetes_secrets provider in {{agent}} [#6623]({{agent-pull}}6623)
* Resolves the proxy to inject into agent component configurations using the Go http package in {{agent}} [#6675]({{agent-pull}}6675) and [#6209]({{agent-issue}}6209)