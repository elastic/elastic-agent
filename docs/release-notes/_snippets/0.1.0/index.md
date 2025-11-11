## 0.1.0 [elastic-agent-release-notes-0.1.0]



### Features and enhancements [elastic-agent-0.1.0-features-enhancements]


* Add sample config files for Windows ES and mOTLP ingestion. [#10728](https://github.com/elastic/elastic-agent/pull/10728) [#10540](https://github.com/elastic/elastic-agent/issues/10540)
* Added opex to elastic-agent helm chart, This change will add the Opex-CCM support to the offical elastic-agent helm chart deployment.  

* Add awss3receiver. [#10515](https://github.com/elastic/elastic-agent/pull/10515) [#604](https://github.com/elastic/obs-integration-team/issues/604)
* Run self-monitoring as otel receivers by default. [#10594](https://github.com/elastic/elastic-agent/pull/10594) 

  The inputs used for Elastic Agent&#39;s self-monitoring now run as receivers inside a managed otel collector.
  This can be switched back by setting `agent.monitoring._runtime_experimental: process`.
  


### Fixes [elastic-agent-0.1.0-fixes]


* Fix quoting of boolean values in Helm charts. [#10681](https://github.com/elastic/elastic-agent/pull/10681) 

