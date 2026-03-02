## 9.2.3 [elastic-agent-release-notes-9.2.3]



### Features and enhancements [elastic-agent-9.2.3-features-enhancements]


* Enable cpu and disk hostmetrics scrapers for Darwin configurations. [#11423](https://github.com/elastic/elastic-agent/pull/11423) 

* Add Windows Event Log Receiver to EDOT. [#11418](https://github.com/elastic/elastic-agent/pull/11418) 
* Improve input not supported error message to reference installation flavors. [#11825](https://github.com/elastic/elastic-agent/pull/11825) 


### Fixes [elastic-agent-9.2.3-fixes]


* Report crashing otel process cleanly with proper status reporting. [#11448](https://github.com/elastic/elastic-agent/pull/11448) 
* Fix kube-stack null template evaluation for Helm v4. [#11481](https://github.com/elastic/elastic-agent/pull/11481) 

* Add environment.yaml file to diagnostics. [#11484](https://github.com/elastic/elastic-agent/pull/11484) [#10966](https://github.com/elastic/elastic-agent/issues/10966)
* Merge multiple agent keys when loading config. [#11619](https://github.com/elastic/elastic-agent/pull/11619) [#3717](https://github.com/elastic/elastic-agent/issues/3717)
* Hide healthcheckv2 from status output. [#11718](https://github.com/elastic/elastic-agent/pull/11718) 

