## 9.5.0 [elastic-agent-release-notes-9.5.0]



### Features and enhancements [elastic-agent-9.5.0-features-enhancements]


* Rename EDOT Collector to Elastic Agent and EDOT Cloud Forwarder to Elastic Cloud Forwarder.

  The EDOT Collector is now built into Elastic Agent as its OpenTelemetry mode. Deploy
  Elastic Agent and run it in OpenTelemetry mode to collect and forward traces, metrics,
  and logs to Elastic Observability. Configuration and components are unchanged.

  The EDOT Cloud Forwarder has been renamed to the Elastic Cloud Forwarder.

* Enable AWS CloudWatch metrics ingestion through `awscloudwatchreceiver` in the EDOT Collector. [#14870](https://github.com/elastic/elastic-agent/pull/14870)
* Add Azure Event Hub receiver to EDOT Collector. [#13418](https://github.com/elastic/elastic-agent/pull/13418)
* Run Filebeat based inputs as collector receivers by default, reducing steady state memory usage [#13991](https://github.com/elastic/elastic-agent/pull/13991)
* Add support for Auditbeat, Heartbeat, Osquerybeat, and Packetbeat based inputs to run in `otel` mode. [#14029](https://github.com/elastic/elastic-agent/pull/14029)
* Run synthetics inputs as collector receivers by default, reducing steady state memory usage. [#15325](https://github.com/elastic/elastic-agent/pull/15325)
* Run packet inputs as collector receivers by default, reducing steady state memory usage. [#15151](https://github.com/elastic/elastic-agent/pull/15151) [#14554](https://github.com/elastic/elastic-agent/issues/14554)
* Run audit inputs as collector receivers by default, reducing steady state memory usage. [#15188](https://github.com/elastic/elastic-agent/pull/15188)
* Run Osquery inputs as collector receivers by default, reducing steady state memory usage. [#15459](https://github.com/elastic/elastic-agent/pull/15459)
* Add Akamai SIEM receiver to EDOT Collector. [#14263](https://github.com/elastic/elastic-agent/pull/14263)
* Add AWS CloudWatch receiver to EDOT Collector. [#14774](https://github.com/elastic/elastic-agent/pull/14774)
* Add credentials provider extension for use with `awscloudwatchreceiver` in EDOT Collector. [#14933](https://github.com/elastic/elastic-agent/pull/14933)
* Update `awscloudwatchreceiver` to support cross-account monitoring for metrics. [#15085](https://github.com/elastic/elastic-agent/pull/15085)
* Update `awscloudwatchreceiver` in EDOT Collector to support `RecentlyActive` for metrics discovery. [#15121](https://github.com/elastic/elastic-agent/pull/15121)
* Write OTel Collector logs to its own log file. [#15491](https://github.com/elastic/elastic-agent/pull/15491)
* Run each per Beat input stream in it's own OpenTelemetry collector receiver (`otel` mode), allowing hot reloading of receiver configurations without collector restarts [#13000](https://github.com/elastic/elastic-agent/pull/13000)
* Enrich APM data with Kubernetes attributes in the EDOT daemon collector. [#13746](https://github.com/elastic/elastic-agent/pull/13746)
* Enrich APM data with Kubernetes attributes in the EDOT daemon collector in non managed kube-stack. [#13901](https://github.com/elastic/elastic-agent/pull/13901)
* Include `fleet-server` in `windows/arm64` packages. [#14120](https://github.com/elastic/elastic-agent/pull/14120)
* Expose `buffer_size` option on StateWatch RPC to skip intermediate states. [#14257](https://github.com/elastic/elastic-agent/pull/14257)
* Periodic cleanup now removes leftover directories from failed upgrades. [#14378](https://github.com/elastic/elastic-agent/pull/14378)
* Write Elastic Agent self-monitoring metrics to a dedicated diagnostics file in the OTLP metrics format. [#14506](https://github.com/elastic/elastic-agent/pull/14506) [#14446](https://github.com/elastic/elastic-agent/issues/14446)
* Read manual rollback targets from on-disk TTL files instead of the upgrade marker. [#14543](https://github.com/elastic/elastic-agent/pull/14543)
* Update OTel Collector components to v0.155.0. [#15333](https://github.com/elastic/elastic-agent/pull/15333)
* Use the FIPS 140-3 certified Go crypto module for Linux FIPS builds, removing runtime dependency on OpenSSL. [#14953](https://github.com/elastic/elastic-agent/pull/14953)
* Bump kube-stack to v0.16.0 and fix `ELASTIC_AGENT_OTEL` quoting for `otel` mode. [#15013](https://github.com/elastic/elastic-agent/pull/15013)
* Add environment variables to collector diagnostics. [#15512](https://github.com/elastic/elastic-agent/pull/15512)


### Fixes [elastic-agent-9.5.0-fixes]


* Redact sensitive HTTP header values embedded in Fleet environment variables in diagnostics archives. [#15284](https://github.com/elastic/elastic-agent/pull/15284)
* Ensure the current runtime stops before the new runtime starts. [#13584](https://github.com/elastic/elastic-agent/pull/13584)
* Fix uncleared config manager errors permanently failing aggregate state. [#14042](https://github.com/elastic/elastic-agent/pull/14042)
* Tolerate corrupt `.ttl` rollback markers during upgrade and rollback. [#14143](https://github.com/elastic/elastic-agent/pull/14143)
* Fix duplicate entries, empty unit dirs, and EDOT error handling in OTel diagnostics. [#15108](https://github.com/elastic/elastic-agent/pull/15108)
* Fix the minimum batch size for supervised OTel Collector Elasticsearch and Kafka exporters. [#15122](https://github.com/elastic/elastic-agent/pull/15122) [#15118](https://github.com/elastic/elastic-agent/issues/15118)
* Propagate the `agent.features.fqdn.enabled` feature flag to Beat receivers. [#15191](https://github.com/elastic/elastic-agent/pull/15191) [#15165](https://github.com/elastic/elastic-agent/issues/15165)
* Preserve locally-configured `monitoring.http.host` across Fleet policy check-ins. [#15291](https://github.com/elastic/elastic-agent/pull/15291)
* Fix translation of `queue.mem.flush.timeout` to OTel `flush_timeout` for unitless values. [#15404](https://github.com/elastic/elastic-agent/pull/15404)
* Fix an issue where FIPS mode accepted non-compliant TLS certificates. [#14986](https://github.com/elastic/elastic-agent/pull/14986)
* Fix spurious "failed to unmarshal checkin actions" error on idle Fleet check-ins. [#15398](https://github.com/elastic/elastic-agent/pull/15398) [#15397](https://github.com/elastic/elastic-agent/issues/15397)
* Override `fleet.ssl.certificate_authorities` from environment variables in container mode. [#15427](https://github.com/elastic/elastic-agent/pull/15427)
* Stop upgrade rollback from being triggered by slow service component restarts. [#15423](https://github.com/elastic/elastic-agent/pull/15423)
* Fix continuous container restarts after Fleet policy updates. [#15772](https://github.com/elastic/elastic-agent/pull/15772)
* Fix orphaned filelog receiver in edot collector helm charts. [#15687](https://github.com/elastic/elastic-agent/pull/15687)
