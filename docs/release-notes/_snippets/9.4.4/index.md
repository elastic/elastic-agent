## 9.4.4 [elastic-agent-release-notes-9.4.4]



### Features and enhancements [elastic-agent-9.4.4-features-enhancements]


* Don't forcibly inject the `elasticdiagnostic` extension when running in `otel` mode. [#15105](https://github.com/elastic/elastic-agent/pull/15105) [#14606](https://github.com/elastic/elastic-agent/issues/14606)
* Update OTel Collector components to v0.155.0. [#15413](https://github.com/elastic/elastic-agent/pull/15413) 
* Set a profiles feature gate for OTel profiles pipelines. [#15012](https://github.com/elastic/elastic-agent/pull/15012) 


### Fixes [elastic-agent-9.4.4-fixes]


* Redact sensitive HTTP header values embedded in Fleet environment variables in diagnostics archives. [#15284](https://github.com/elastic/elastic-agent/pull/15284)
* Add missing `host.hostname` to monitoring metrics for OTel outputs. [#14454](https://github.com/elastic/elastic-agent/pull/14454) 
* Fix missing Beat receiver trace logs from diagnostic bundle. [#14716](https://github.com/elastic/elastic-agent/pull/14716) 
* Fix duplicate entries, empty unit dirs, and EDOT error handling in OTel diagnostics. [#15108](https://github.com/elastic/elastic-agent/pull/15108)
* Fix minimum batch size for supervised OTel Collector Elasticsearch and Kafka exporters. [#15122](https://github.com/elastic/elastic-agent/pull/15122) [#15118](https://github.com/elastic/elastic-agent/issues/15118)
* Propagate the `agent.features.fqdn.enabled` feature flag to Beat receivers. [#15191](https://github.com/elastic/elastic-agent/pull/15191) [#15165](https://github.com/elastic/elastic-agent/issues/15165)
* Preserve locally-configured `monitoring.http.host` across Fleet policy check-ins. [#15291](https://github.com/elastic/elastic-agent/pull/15291)
* Fix translation of `queue.mem.flush.timeout` to OTel `flush_timeout` for unitless values. [#15404](https://github.com/elastic/elastic-agent/pull/15404)
* Fix "failed to unmarshal checkin actions" error on idle Fleet check-ins. [#15398](https://github.com/elastic/elastic-agent/pull/15398) [#15397](https://github.com/elastic/elastic-agent/issues/15397)
* Override `fleet.ssl.certificate_authorities` from environment variables in container mode. [#15427](https://github.com/elastic/elastic-agent/pull/15427) 

