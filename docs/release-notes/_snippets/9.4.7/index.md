## 9.4.7 [elastic-agent-release-notes-9.4.7]





### Fixes [elastic-agent-9.4.7-fixes]


* Validate component working directory path to prevent path traversal. [#16502](https://github.com/elastic/elastic-agent/pull/16502) [#16226](https://github.com/elastic/elastic-agent/issues/16226)
* Fix Kafka lz4/snappy compression failing in the OTel runtime after 9.5. [#16373](https://github.com/elastic/elastic-agent/pull/16373) [#16239](https://github.com/elastic/elastic-agent/issues/16239)
* Prevent panic when translating otel config and unit has nil configuration. [#16478](https://github.com/elastic/elastic-agent/pull/16478) [#16470](https://github.com/elastic/elastic-agent/issues/16470)

