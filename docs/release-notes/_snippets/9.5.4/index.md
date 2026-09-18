## 9.5.4 [elastic-agent-release-notes-9.5.4]



### Features and enhancements [elastic-agent-9.5.4-features-enhancements]


* Add the OpenTelemetry `googlecloudmonitoringreceiver`. [#16516](https://github.com/elastic/elastic-agent/pull/16516)


### Fixes [elastic-agent-9.5.4-fixes]


* Validate component working directory path to prevent path traversal. [#16502](https://github.com/elastic/elastic-agent/pull/16502) [#16226](https://github.com/elastic/elastic-agent/issues/16226)
* Prevent panic when the OTel translation path encounters an input unit without a configuration. [#16477](https://github.com/elastic/elastic-agent/pull/16477) [#16470](https://github.com/elastic/elastic-agent/issues/16470)

