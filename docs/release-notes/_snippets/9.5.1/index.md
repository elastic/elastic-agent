## 9.5.1 [elastic-agent-release-notes-9.5.1]



### Features and enhancements [elastic-agent-9.5.1-features-enhancements]


* Rename EDOT Collector to Elastic Agent and EDOT Cloud Forwarder to Elastic Cloud Forwarder. [#15826](https://github.com/elastic/elastic-agent/pull/15826) 

### Fixes [elastic-agent-9.5.1-fixes]

* Sensitive values in JSON diagnostic files are now redacted. [#15899](https://github.com/elastic/elastic-agent/pull/15899) [#15964](https://github.com/elastic/elastic-agent/issues/15964)
* Fix OTel heartbeat runtime breaking Synthetics browser monitors on Private Locations. [#15969](https://github.com/elastic/elastic-agent/pull/15969) [#15968](https://github.com/elastic/elastic-agent/issues/15968)
* Bake Synthetics browser binaries into the elastic-agent-complete image. [#15994](https://github.com/elastic/elastic-agent/pull/15994) [#15993](https://github.com/elastic/elastic-agent/issues/15993)
* Fix ordering of streams for osquerybeat receiver. [#15989](https://github.com/elastic/elastic-agent/pull/15989) 

