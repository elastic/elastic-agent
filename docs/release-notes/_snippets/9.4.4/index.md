## 9.4.4 [elastic-agent-release-notes-9.4.4]



### Features and enhancements [elastic-agent-9.4.4-features-enhancements]


* Don&#39;t forcibly inject the elasticdiagnostic extension when running in plain otel mode. [#15105](https://github.com/elastic/elastic-agent/pull/15105) [#14606](https://github.com/elastic/elastic-agent/issues/14606)

  When running in hybrid mode, supervised by the Elastic Agent, the extension continues to be injected.
  
* Update OTel Collector components to v0.155.0. [#15413](https://github.com/elastic/elastic-agent/pull/15413) 

* Set profiles feature gate for OTel profiles pipelines. [#15012](https://github.com/elastic/elastic-agent/pull/15012) 


### Fixes [elastic-agent-9.4.4-fixes]


* Redact sensitive HTTP header values embedded in Fleet env vars in diagnostics archives. [#15284](https://github.com/elastic/elastic-agent/pull/15284) 

  Diagnostics archives could expose authentication tokens when Fleet header environment
  variables (such as FLEET_HEADER, FLEET_HEADERS, FLEET_KIBANA_HEADER, and
  FLEET_KIBANA_HEADERS) contained sensitive HTTP header values. The diagnostics redaction
  logic now expands and redacts individual header values within these variables.
  
* Add missing host.hostname to monitoring-metrics. [#14454](https://github.com/elastic/elastic-agent/pull/14454) 
* Fix missing beat receiver trace logs from diagnostic bundle. [#14716](https://github.com/elastic/elastic-agent/pull/14716) 
* Fix duplicate entries, empty unit dirs, and EDOT error handling in OTel diagnostics. [#15108](https://github.com/elastic/elastic-agent/pull/15108) 

  The OTel diagnostics ZIP no longer contains duplicate entries and no longer creates empty unit subdirectories. Components with no EDOT diagnostics no longer produce a spurious error in the archive. Also, an unexpected EDOT error used to abort the whole component-diagnostics request; now it is recorded per component so the diagnostics archive is still produced.
  
* Fix minimum batch size for supervised OTel collector ES and Kafka exporters. [#15122](https://github.com/elastic/elastic-agent/pull/15122) [#15118](https://github.com/elastic/elastic-agent/issues/15118)
* Propagate the `agent.features.fqdn.enabled` feature flag to beat receivers. [#15191](https://github.com/elastic/elastic-agent/pull/15191) [#15165](https://github.com/elastic/elastic-agent/issues/15165)
* Preserve locally-configured monitoring.http.host across Fleet policy check-ins. [#15291](https://github.com/elastic/elastic-agent/pull/15291) 

  A regression introduced in 9.4.2 caused the agent&#39;s monitoring HTTP listener to rebind to the
  default host (localhost) on every Fleet policy check-in, discarding any host configured locally
  via agent.monitoring.http.host (e.g. 0.0.0.0). The policy-change handler now only applies
  monitoring.http/pprof settings from the policy when they are explicitly present, leaving the
  locally-configured values untouched otherwise.
  
* Fix translation of `queue.mem.flush.timeout` to OTel `flush_timeout` for unitless values. [#15404](https://github.com/elastic/elastic-agent/pull/15404) 

  When translating an output&#39;s Beats configuration to an OpenTelemetry Collector
  configuration, a unitless queue.mem.flush.timeout value (e.g. `5`, which Beats
  interprets as 5 seconds) was passed through verbatim as a string to the exporterhelper
  sending_queue.batch.flush_timeout option. Because that option is a time.Duration,
  the collector failed to start with &#34;&#39;flush_timeout&#39; time: missing unit in duration&#34;.
  Unitless values are now suffixed with the seconds unit.
  
* Fix spurious &#34;failed to unmarshal checkin actions&#34; error on idle Fleet check-ins. [#15398](https://github.com/elastic/elastic-agent/pull/15398) [#15397](https://github.com/elastic/elastic-agent/issues/15397)
* Override fleet.ssl.certificate_authorities from env vars in container mode. [#15427](https://github.com/elastic/elastic-agent/pull/15427) 

