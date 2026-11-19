## 9.4.10 [elastic-agent-release-notes-9.4.10]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.4.10-breaking-changes)._


### Features and enhancements [elastic-agent-9.4.10-features-enhancements]


* Update OTel Collector components to v0.164.x. [#17668](https://github.com/elastic/elastic-agent/pull/17668) 
* Update OTel Collector components to v0.165.x. [#17977](https://github.com/elastic/elastic-agent/pull/17977) 


### Fixes [elastic-agent-9.4.10-fixes]


* Load the EDOT .NET plugin in kube-stack auto-instrumentation. [#17451](https://github.com/elastic/elastic-agent/pull/17451) 

* Guard against malformed health status payload and nil event panic in OTel collector. [#17208](https://github.com/elastic/elastic-agent/pull/17208) 

  Prevent runtime panics in Elastic Agent&#39;s OTel collector manager when receiving empty or malformed health status payloads lacking event data.
  
* Report service component start failures as degraded, and as failed when they persist. [#17524](https://github.com/elastic/elastic-agent/pull/17524) [#16305](https://github.com/elastic/elastic-agent/issues/16305)
* Fix components and units that are removed and quickly re-added by a policy change staying stopped until the agent restarts. [#17715](https://github.com/elastic/elastic-agent/pull/17715) [#17714](https://github.com/elastic/elastic-agent/issues/17714)
* Fix upgrade watcher double counting restarts. [#17938](https://github.com/elastic/elastic-agent/pull/17938) 

