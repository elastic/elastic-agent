## 9.5.7 [elastic-agent-release-notes-9.5.7]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.5.7-breaking-changes)._


### Features and enhancements [elastic-agent-9.5.7-features-enhancements]


* Support Kafka timeout configuration in OTel runtime. [#17087](https://github.com/elastic/elastic-agent/pull/17087) 

* Support Packetbeat on Windows ARM64. [#17663](https://github.com/elastic/elastic-agent/pull/17663) 

  The Elastic Agent package for Windows ARM64 includes the Npcap installer and can capture network traffic on Windows ARM64 hosts.
* Add the sigv4auth extension to the EDOT Collector.  
* Update OTel Collector components to v0.164.x. [#17668](https://github.com/elastic/elastic-agent/pull/17668) 
* Update OTel Collector components to v0.165.x.  


### Fixes [elastic-agent-9.5.7-fixes]


* Load the EDOT .NET plugin in kube-stack auto-instrumentation. [#17451](https://github.com/elastic/elastic-agent/pull/17451) 

* Guard against malformed health status payload and nil event panic in OTel collector. [#17208](https://github.com/elastic/elastic-agent/pull/17208) 

  Prevent runtime panics in Elastic Agent&#39;s OTel collector manager when receiving empty or malformed health status payloads lacking event data.
  
* Report service component start failures as degraded, and as failed when they persist. [#17524](https://github.com/elastic/elastic-agent/pull/17524) [#16305](https://github.com/elastic/elastic-agent/issues/16305)
* Fix components and units that are removed and quickly re-added by a policy change staying stopped until the agent restarts. [#17715](https://github.com/elastic/elastic-agent/pull/17715) [#17714](https://github.com/elastic/elastic-agent/issues/17714)
* Fix the EDOT collector keeping diagnostics hooks of stopped beat receivers in memory.  

  The elastic_diagnostics extension kept every diagnostics hook a beat receiver registered, so each receiver restart on a config reload left the old receiver in memory and added duplicate files to diagnostics bundles. The extension now drops a component&#39;s hooks when the collector reports that it has stopped, and registering a hook again for the same receiver and file replaces the old one.
* Fix Kafka output not falling back to the process runtime when ssl.ca_sha256 is configured.  
* Fix elastic-agent logs failing on Windows before the event logs directory exists.  
* Fix upgrade watcher double counting restarts.  

