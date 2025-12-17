## 9.1.9 [elastic-agent-release-notes-9.1.9]



### Features and enhancements [elastic-agent-9.1.9-features-enhancements]


* Enable cpu and disk hostmetrics scrapers for Darwin configurations. [#11423](https://github.com/elastic/elastic-agent/pull/11423) 

* Improve input not supported error message to reference installation flavors. [#11825](https://github.com/elastic/elastic-agent/pull/11825) [#11746](https://github.com/elastic/elastic-agent/issues/11746)


### Fixes [elastic-agent-9.1.9-fixes]


* Fix kube-stack null template evaluation for Helm v4. [#11481](https://github.com/elastic/elastic-agent/pull/11481) 

* Allow host to be a string for otel configuration translation. [#11394](https://github.com/elastic/elastic-agent/pull/11394) [#11352](https://github.com/elastic/elastic-agent/issues/11352)
* Add environment.yaml file to diagnostics. [#11484](https://github.com/elastic/elastic-agent/pull/11484) [#10966](https://github.com/elastic/elastic-agent/issues/10966)
* Merge multiple agent keys when loading config. [#11619](https://github.com/elastic/elastic-agent/pull/11619) [#3717](https://github.com/elastic/elastic-agent/issues/3717)

