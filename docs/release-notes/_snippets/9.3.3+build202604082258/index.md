## 9.3.3&#43;build202604082258 [elastic-agent-release-notes-9.3.3&#43;build202604082258]

:::{note}
This is an independent Elastic Agent release. Independent Elastic Agent releases deliver critical fixes and updates for Elastic Agent and Elastic Defend independently of a full Elastic Stack release. Read more in [Elastic Agent release process](docs-content://reference/fleet/fleet-agent-release-process.md).
:::


### Fixes [elastic-agent-9.3.3&#43;build202604082258-fixes]

* Fixes a memory leak related to path normalization in Elastic Defend that was introduced in 9.3.0.
* Fixes the Elastic Defend Kafka output. Handling transient or invalid metadata responses by falling back to broker-selected partitioning.
