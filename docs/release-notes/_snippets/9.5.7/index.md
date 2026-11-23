## 9.5.7 [elastic-agent-release-notes-9.5.7]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.5.7-breaking-changes)._


### Features and enhancements [elastic-agent-9.5.7-features-enhancements]


* Support Kafka timeout configuration in the OTel runtime. [#17087](https://github.com/elastic/elastic-agent/pull/17087)
* Support Packetbeat on Windows ARM64. [#17663](https://github.com/elastic/elastic-agent/pull/17663)
* Add the `sigv4auth` extension to Elastic Agent configured as an OTel Collector. [#18021](https://github.com/elastic/elastic-agent/pull/18021)
* Update OTel Collector components to v0.165.x. [#17977](https://github.com/elastic/elastic-agent/pull/17977)


### Fixes [elastic-agent-9.5.7-fixes]

* Load the EDOT .NET plugin in kube-stack auto-instrumentation. [#17451](https://github.com/elastic/elastic-agent/pull/17451)
* Prevent a panic in the OTel Collector when it receives an empty or malformed health status payload. [#17208](https://github.com/elastic/elastic-agent/pull/17208)
* Report service component start failures as degraded, and as failed when they persist. [#17524](https://github.com/elastic/elastic-agent/pull/17524) [#16305](https://github.com/elastic/elastic-agent/issues/16305)
* Fix components and units that are removed and quickly re-added by a policy change staying stopped until the agent restarts. [#17715](https://github.com/elastic/elastic-agent/pull/17715) [#17714](https://github.com/elastic/elastic-agent/issues/17714)
* Fix Elastic Agent configured as an OTel Collector keeping diagnostics hooks of stopped Beat receivers in memory. [#18033](https://github.com/elastic/elastic-agent/pull/18033)
* Fix the Kafka output not falling back to the process runtime when `ssl.ca_sha256` is configured. [#17893](https://github.com/elastic/elastic-agent/pull/17893)
* Fix the `elastic-agent logs` command failing on Windows before the event logs directory exists. [#17897](https://github.com/elastic/elastic-agent/pull/17897)
* Fix the upgrade watcher double-counting Elastic Agent restarts after an upgrade. [#17938](https://github.com/elastic/elastic-agent/pull/17938)
