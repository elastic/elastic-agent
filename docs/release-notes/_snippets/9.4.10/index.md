## 9.4.10 [elastic-agent-release-notes-9.4.10]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.4.10-breaking-changes)._


### Features and enhancements [elastic-agent-9.4.10-features-enhancements]


* Update OTel Collector components to v0.164.x. [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099) 
* Update OTel Collector components to v0.165.x. [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099) 


### Fixes [elastic-agent-9.4.10-fixes]


* Load the EDOT .NET plugin in kube-stack auto-instrumentation. [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099) 

* Guard against malformed health status payload and nil event panic in OTel collector. [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099) 

  Prevent runtime panics in Elastic Agent&#39;s OTel collector manager when receiving empty or malformed health status payloads lacking event data.
  
* Report service component start failures as degraded, and as failed when they persist. [#17524](https://github.com/elastic/elastic-agent/pull/17524) [#16305](https://github.com/elastic/elastic-agent/issues/16305)
* Fix components and units that are removed and quickly re-added by a policy change staying stopped until the agent restarts. [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099) [#17714](https://github.com/elastic/elastic-agent/issues/17714)
* Fix upgrade watcher double counting restarts. [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099) 

