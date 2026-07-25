## 9.5.0 [elastic-agent-release-notes-9.5.0]



### Features and enhancements [elastic-agent-9.5.0-features-enhancements]


* Enable AWS CloudWatch metrics ingestion via the awscloudwatchreceiver in the EDOT Collector. [#14870](https://github.com/elastic/elastic-agent/pull/14870) 

* Add Azure Event Hub receiver to EDOT Collector. [#13418](https://github.com/elastic/elastic-agent/pull/13418) 
* Make otel runtime the default for filebeat inputs. [#13991](https://github.com/elastic/elastic-agent/pull/13991) 
* Add support for auditbeat, heartbeat, osquerybeat, and packetbeat to run under otel mode. [#14029](https://github.com/elastic/elastic-agent/pull/14029) 
* Add Akamai SIEM receiver to EDOT Collector. [#14263](https://github.com/elastic/elastic-agent/pull/14263) 
* Add AWS CloudWatch receiver to EDOT Collector. [#14774](https://github.com/elastic/elastic-agent/pull/14774) 
* Add credentials provider extension for use with awscloudwatchreceiver in edot. [#14933](https://github.com/elastic/elastic-agent/pull/14933) 
* Update awscloudwatchreceiver to support cross-account monitoring for metrics. [#15085](https://github.com/elastic/elastic-agent/pull/15085) 
* Update edot awscloudwatchreceiver to support `RecentlyActive` for metrics discovery. [#15121](https://github.com/elastic/elastic-agent/pull/15121) 
* Run audit inputs as collector receivers by default, reducing steady state memory usage. [#15188](https://github.com/elastic/elastic-agent/pull/15188) 
* Run osquery inputs as collector receivers by default, reducing steady state memory usage. [#15459](https://github.com/elastic/elastic-agent/pull/15459) 
* Write OTel collector logs to its own log file. [#15491](https://github.com/elastic/elastic-agent/pull/15491) 

  When running under the otel runtime, the OTel collector now writes to its
  own log file instead of the main agent log file. Its event logs go to a
  separate collector event log file rather than the agent&#39;s event log.
  
* Run each stream in its own receiver (OTEL mode). [#13000](https://github.com/elastic/elastic-agent/pull/13000) 

  When an input is running in OTEL mode each stream is defined as its own receiver.
  
* Update OTel Collector components to v0.149.0. [#13599](https://github.com/elastic/elastic-agent/pull/13599) 
* Update OTel Collector components to v0.150.0/v1.56.0. [#13696](https://github.com/elastic/elastic-agent/pull/13696) 
* Enrich APM data with k8s attributes at the edot daemon collector. [#13746](https://github.com/elastic/elastic-agent/pull/13746) 
* Enrich APM data with k8s attributes at the edot daemon collector in non managed kube-stack. [#13901](https://github.com/elastic/elastic-agent/pull/13901) 
* Include fleet-server in windows/arm64 packages. [#14120](https://github.com/elastic/elastic-agent/pull/14120) 
* Update OTel Collector components to v0.152.0. [#14198](https://github.com/elastic/elastic-agent/pull/14198) 
* Expose buffer_size option on StateWatch RPC to skip intermediate states. [#14257](https://github.com/elastic/elastic-agent/pull/14257) 
* Periodic cleanup now removes leftover directories from failed upgrades. [#14378](https://github.com/elastic/elastic-agent/pull/14378) 

  The periodic cleanup previously only removed directories tracked by the TTL
  registry. Directories left behind by failed upgrades — those that never got
  a .ttl marker written — were invisible to it and only removed when the next
  upgrade ran. The cleanup now scans all elastic-agent-* directories and
  removes any that are not the current home, referenced by an active upgrade
  marker, or covered by an unexpired TTL entry.
  
  Additionally, the upgrade marker is now written before unpacking begins so
  that the target directory is protected from a concurrent cleanup run
  throughout the entire upgrade process.
  
* Write EDOT internal telemetry to a dedicated diagnostics file. [#14506](https://github.com/elastic/elastic-agent/pull/14506) [#14446](https://github.com/elastic/elastic-agent/issues/14446)
* Read manual rollback targets from on-disk TTL files instead of the upgrade marker. [#14543](https://github.com/elastic/elastic-agent/pull/14543) 
* Update OTel Collector components to v0.155.0. [#15333](https://github.com/elastic/elastic-agent/pull/15333) 
* Use native GO for linux FIPS builds. [#14953](https://github.com/elastic/elastic-agent/pull/14953) 
* Bump kube-stack to 0.16.0 and fix ELASTIC_AGENT_OTEL quoting for otel mode. [#15013](https://github.com/elastic/elastic-agent/pull/15013) 
* Set OTel as the default runtime for Packetbeat. [#15151](https://github.com/elastic/elastic-agent/pull/15151) [#14554](https://github.com/elastic/elastic-agent/issues/14554)
* Set OTel as the default runtime for Heartbeat. [#15325](https://github.com/elastic/elastic-agent/pull/15325) 
* Add environment variables to collector diagnostics.  


### Fixes [elastic-agent-9.5.0-fixes]


* Redact sensitive HTTP header values embedded in Fleet env vars in diagnostics archives. [#15284](https://github.com/elastic/elastic-agent/pull/15284) 

  Diagnostics archives could expose authentication tokens when Fleet header environment
  variables (such as FLEET_HEADER, FLEET_HEADERS, FLEET_KIBANA_HEADER, and
  FLEET_KIBANA_HEADERS) contained sensitive HTTP header values. The diagnostics redaction
  logic now expands and redacts individual header values within these variables.
  
* Ensure current runtime stops before new runtime starts. [#13584](https://github.com/elastic/elastic-agent/pull/13584) 

  Ensures that the current runtime stops before the new runtime starts, otherwise registry
  state will not be consistent before the start of the new runtime.
  
* Fix uncleared config manager errors permanently failing aggregate state. [#14042](https://github.com/elastic/elastic-agent/pull/14042) 
* Tolerate corrupt `.ttl` rollback markers during upgrade and rollback. [#14143](https://github.com/elastic/elastic-agent/pull/14143) 

  A corrupt `.ttl` rollback marker file in the live agent install previously
  caused the TTL registry to abort with a parse error, which blocked every
  subsequent upgrade and rollback attempt. The registry now tolerates
  malformed existing markers: corrupt entries in the desired state are
  overwritten with valid YAML, and entries absent from the desired state are
  swept from disk, allowing upgrade and rollback flows to self-heal.
  
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
  
* Fixed FIPS mode accepting non-compliant TLS certificates. [#14986](https://github.com/elastic/elastic-agent/pull/14986) 
* Fix spurious &#34;failed to unmarshal checkin actions&#34; error on idle Fleet check-ins. [#15398](https://github.com/elastic/elastic-agent/pull/15398) [#15397](https://github.com/elastic/elastic-agent/issues/15397)
* Override fleet.ssl.certificate_authorities from env vars in container mode. [#15427](https://github.com/elastic/elastic-agent/pull/15427) 

