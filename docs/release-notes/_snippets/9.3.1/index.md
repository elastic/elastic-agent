## 9.3.1 [elastic-agent-release-notes-9.3.1]

_This release also includes: [Deprecations](/release-notes/deprecations.md#elastic-agent-9.3.1-deprecations)._


### Features and enhancements [elastic-agent-9.3.1-features-enhancements]


* Support the `-—prefix` flag when installing from RPM. [#12263](https://github.com/elastic/elastic-agent/pull/12263) [#141](https://github.com/elastic/elastic-agent/issues/141)
* Add `agent.internal.runtime.dynamic_inputs` flag to control the runtime used by inputs using dynamic variables. [#12438](https://github.com/elastic/elastic-agent/pull/12438) [#11630](https://github.com/elastic/elastic-agent/issues/11630)
* Update OTel Collector components to v0.144.0. [#12449](https://github.com/elastic/elastic-agent/pull/12449) 
* Add `statsd` receiver to EDOT Collector. [#12628](https://github.com/elastic/elastic-agent/pull/12628) 
* Add `logdedup` processor to EDOT as an extended component. [#12654](https://github.com/elastic/elastic-agent/pull/12654) [#6869](https://github.com/elastic/ingest-dev/issues/6869)
* Include more standard metadata in monitoring events from the OTel Collector. [#12717](https://github.com/elastic/elastic-agent/pull/12717) 


### Fixes [elastic-agent-9.3.1-fixes]


* Add a missing dependency for Synthetics on Wolfi Docker image. [#12453](https://github.com/elastic/elastic-agent/pull/12453) 
* Fix becoming unhealthy when using the `warn` log level. [#12519](https://github.com/elastic/elastic-agent/pull/12519) [#12513](https://github.com/elastic/elastic-agent/issues/12513)
* Fix an issue where monitoring could reingest its own error logs in a feedback loop. [#12663](https://github.com/elastic/elastic-agent/pull/12663) [#12524](https://github.com/elastic/elastic-agent/issues/12524)
* Fix OTel Collector not receiving `service.telemetry` config from persisted file. [#12736](https://github.com/elastic/elastic-agent/pull/12736) [#12737](https://github.com/elastic/elastic-agent/issues/12737)

