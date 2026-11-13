## 9.5.7 [elastic-agent-release-notes-9.5.7]



### Features and enhancements [elastic-agent-9.5.7-features-enhancements]


* Support Packetbeat on Windows ARM64. [#17848](https://github.com/elastic/elastic-agent/pull/17848) [#17951](https://github.com/elastic/elastic-agent/pull/17951) [#17893](https://github.com/elastic/elastic-agent/pull/17893) [#17982](https://github.com/elastic/elastic-agent/pull/17982) [#17895](https://github.com/elastic/elastic-agent/pull/17895) [#17966](https://github.com/elastic/elastic-agent/pull/17966) [#17717](https://github.com/elastic/elastic-agent/issues/17717) [#17894](https://github.com/elastic/elastic-agent/issues/17894)

  The Elastic Agent package for Windows ARM64 includes the Npcap installer and can capture network traffic on Windows ARM64 hosts.
* Update OTel Collector components to v0.164.x. [#17848](https://github.com/elastic/elastic-agent/pull/17848) [#17951](https://github.com/elastic/elastic-agent/pull/17951) [#17893](https://github.com/elastic/elastic-agent/pull/17893) [#17982](https://github.com/elastic/elastic-agent/pull/17982) [#17895](https://github.com/elastic/elastic-agent/pull/17895) [#17966](https://github.com/elastic/elastic-agent/pull/17966) [#17717](https://github.com/elastic/elastic-agent/issues/17717) [#17894](https://github.com/elastic/elastic-agent/issues/17894)


### Fixes [elastic-agent-9.5.7-fixes]


* Load the EDOT .NET plugin in kube-stack auto-instrumentation. [#17848](https://github.com/elastic/elastic-agent/pull/17848) [#17951](https://github.com/elastic/elastic-agent/pull/17951) [#17893](https://github.com/elastic/elastic-agent/pull/17893) [#17982](https://github.com/elastic/elastic-agent/pull/17982) [#17895](https://github.com/elastic/elastic-agent/pull/17895) [#17966](https://github.com/elastic/elastic-agent/pull/17966) [#17717](https://github.com/elastic/elastic-agent/issues/17717) [#17894](https://github.com/elastic/elastic-agent/issues/17894)

* Guard against malformed health status payload and nil event panic in OTel collector. [#17848](https://github.com/elastic/elastic-agent/pull/17848) [#17951](https://github.com/elastic/elastic-agent/pull/17951) [#17893](https://github.com/elastic/elastic-agent/pull/17893) [#17982](https://github.com/elastic/elastic-agent/pull/17982) [#17895](https://github.com/elastic/elastic-agent/pull/17895) [#17966](https://github.com/elastic/elastic-agent/pull/17966) [#17717](https://github.com/elastic/elastic-agent/issues/17717) [#17894](https://github.com/elastic/elastic-agent/issues/17894)

  Prevent runtime panics in Elastic Agent&#39;s OTel collector manager when receiving empty or malformed health status payloads lacking event data.
  
* Report service component start failures as degraded, and as failed when they persist. [#17524](https://github.com/elastic/elastic-agent/pull/17524) [#16305](https://github.com/elastic/elastic-agent/issues/16305)
* Fix components and units that are removed and quickly re-added by a policy change staying stopped until the agent restarts. [#17848](https://github.com/elastic/elastic-agent/pull/17848) [#17951](https://github.com/elastic/elastic-agent/pull/17951) [#17893](https://github.com/elastic/elastic-agent/pull/17893) [#17982](https://github.com/elastic/elastic-agent/pull/17982) [#17895](https://github.com/elastic/elastic-agent/pull/17895) [#17966](https://github.com/elastic/elastic-agent/pull/17966) [#17714](https://github.com/elastic/elastic-agent/issues/17714)

