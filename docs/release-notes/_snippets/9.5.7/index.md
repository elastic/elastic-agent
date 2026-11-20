## 9.5.7 [elastic-agent-release-notes-9.5.7]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.5.7-breaking-changes)._


### Features and enhancements [elastic-agent-9.5.7-features-enhancements]


* Support Kafka timeout configuration in OTel runtime. [#17087](https://github.com/elastic/elastic-agent/pull/17087) 

* Support Packetbeat on Windows ARM64. [#17663](https://github.com/elastic/elastic-agent/pull/17663) 
* Add the sigv4auth extension to the EDOT Collector.  
* Update OTel Collector components to v0.164.x. [#17668](https://github.com/elastic/elastic-agent/pull/17668) 
* Update OTel Collector components to v0.165.x.  


### Fixes [elastic-agent-9.5.7-fixes]

* Load the EDOT .NET plugin in kube-stack auto-instrumentation. [#17451](https://github.com/elastic/elastic-agent/pull/17451) 
* Guard against malformed health status payload and nil event panic in OTel collector. [#17208](https://github.com/elastic/elastic-agent/pull/17208) 
* Report service component start failures as degraded, and as failed when they persist. [#17524](https://github.com/elastic/elastic-agent/pull/17524) [#16305](https://github.com/elastic/elastic-agent/issues/16305)
* Fix components and units that are removed and quickly re-added by a policy change staying stopped until the agent restarts. [#17715](https://github.com/elastic/elastic-agent/pull/17715) [#17714](https://github.com/elastic/elastic-agent/issues/17714)
* Fix the EDOT collector keeping diagnostics hooks of stopped beat receivers in memory.  
* Fix Kafka output not falling back to the process runtime when ssl.ca_sha256 is configured.  
* Fix elastic-agent logs failing on Windows before the event logs directory exists.  
* Fix upgrade watcher double counting restarts.  

