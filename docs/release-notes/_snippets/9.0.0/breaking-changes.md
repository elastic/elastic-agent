## 9.0.0 [elastic-agent-9.0.0-breaking-changes]

::::{dropdown} Removed cloud defend support for {{agent}}
Support for `cloud-defend` (Defend for Containers) has been removed. The package has been removed from the {{agent}} packaging scripts and template Kubernetes files.

For more information, check [#5481]({{agent-pull}}5481).
::::

::::{dropdown} Removed username and password default values for {{agent}}
The default values for `username` and `password` have been removed for when {{agent}} is running in container mode. The {{es}} `api_key` can now be set in that mode using the `ELASTICSEARCH_API_KEY` environment variable.

For more information, check [#5536]({{agent-pull}}5536).
::::

::::{dropdown} Changed Ubuntu-based Docker images for {{agent}}
The default Ubuntu-based Docker images used for {{agent}} have been changed to UBI-minimal-based images, to reduce the overall footprint of the agent Docker images and to improve compliance with enterprise standards.

For more information, check [#6427]({{agent-pull}}6427).
::::

::::{dropdown} Removed --path.install flag declaration from {{agent}} paths command
The deprecated `--path.install` flag declaration has been removed from the {{agent}} `paths` command and its use removed from the `container` and `enroll` commands.

For more information, check [#6461]({{agent-pull}}6461) and [#2489]({{agent-pull}}2489).
::::

::::{dropdown} Changed the default {{agent}} installation and upgrade
The default {{agent}} installation and ugprade have been changed to include only the `agentbeat`, `endpoint-security` and `pf-host-agent` components.

Additional components such as `apm` or `fleet` require passing the `--install-servers` flag or setting the `ELASTIC_AGENT_FLAVOR=servers` environment variable.

For more information, check [#6542]({{agent-pull}}6542).
::::
