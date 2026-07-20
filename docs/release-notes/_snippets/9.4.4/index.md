## 9.4.4 [elastic-agent-release-notes-9.4.4]



### Features and enhancements [elastic-agent-9.4.4-features-enhancements]


* Don&#39;t forcibly inject the elasticdiagnostic extension when running in plain otel mode. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#14606](https://github.com/elastic/elastic-agent/issues/14606)

  When running in hybrid mode, supervised by the Elastic Agent, the extension continues to be injected.
  
* Update OTel Collector components to v0.155.0. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)

* Set profiles feature gate for OTel profiles pipelines. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)


### Fixes [elastic-agent-9.4.4-fixes]


* Redact sensitive HTTP header values embedded in Fleet env vars in diagnostics archives. [#15284](https://github.com/elastic/elastic-agent/pull/15284) 

  Diagnostics archives could expose authentication tokens when Fleet header environment
  variables (such as FLEET_HEADER, FLEET_HEADERS, FLEET_KIBANA_HEADER, and
  FLEET_KIBANA_HEADERS) contained sensitive HTTP header values. The diagnostics redaction
  logic now expands and redacts individual header values within these variables.
  
* Add missing host.hostname to monitoring-metrics. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)
* Fix missing beat receiver trace logs from diagnostic bundle. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)
* Fix duplicate entries, empty unit dirs, and EDOT error handling in OTel diagnostics. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)

  The OTel diagnostics ZIP no longer contains duplicate entries and no longer creates empty unit subdirectories. Components with no EDOT diagnostics no longer produce a spurious error in the archive. Also, an unexpected EDOT error used to abort the whole component-diagnostics request; now it is recorded per component so the diagnostics archive is still produced.
  
* Fix minimum batch size for supervised OTel collector ES and Kafka exporters. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#15118](https://github.com/elastic/elastic-agent/issues/15118)
* Propagate the `agent.features.fqdn.enabled` feature flag to beat receivers. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#15165](https://github.com/elastic/elastic-agent/issues/15165)
* Preserve locally-configured monitoring.http.host across Fleet policy check-ins. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)

  A regression introduced in 9.4.2 caused the agent&#39;s monitoring HTTP listener to rebind to the
  default host (localhost) on every Fleet policy check-in, discarding any host configured locally
  via agent.monitoring.http.host (e.g. 0.0.0.0). The policy-change handler now only applies
  monitoring.http/pprof settings from the policy when they are explicitly present, leaving the
  locally-configured values untouched otherwise.
  
* Fix translation of `queue.mem.flush.timeout` to OTel `flush_timeout` for unitless values. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)

  When translating an output&#39;s Beats configuration to an OpenTelemetry Collector
  configuration, a unitless queue.mem.flush.timeout value (e.g. `5`, which Beats
  interprets as 5 seconds) was passed through verbatim as a string to the exporterhelper
  sending_queue.batch.flush_timeout option. Because that option is a time.Duration,
  the collector failed to start with &#34;&#39;flush_timeout&#39; time: missing unit in duration&#34;.
  Unitless values are now suffixed with the seconds unit.
  
* Fix spurious &#34;failed to unmarshal checkin actions&#34; error on idle Fleet check-ins. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#15397](https://github.com/elastic/elastic-agent/issues/15397)
* Override fleet.ssl.certificate_authorities from env vars in container mode. [#15456](https://github.com/elastic/elastic-agent/pull/15456) [#14871](https://github.com/elastic/elastic-agent/pull/14871) [#15550](https://github.com/elastic/elastic-agent/pull/15550) [#15513](https://github.com/elastic/elastic-agent/pull/15513) [#15542](https://github.com/elastic/elastic-agent/pull/15542) [#15618](https://github.com/elastic/elastic-agent/pull/15618) [#7183](https://github.com/elastic/elastic-agent/issues/7183) [#14746](https://github.com/elastic/elastic-agent/issues/14746)

