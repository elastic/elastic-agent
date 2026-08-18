## 9.5.2 [elastic-agent-release-notes-9.5.2]



### Features and enhancements [elastic-agent-9.5.2-features-enhancements]


* Bump github.com/kardianos/service to v1.3.0 and update Linux systemd template for new mini template engine. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 
* Update Go to 1.26.6. [#16203](https://github.com/elastic/elastic-agent/pull/16203) 


### Fixes [elastic-agent-9.5.2-fixes]


* Fix local privilege escalation via binary tampering on Windows unprivileged installs. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 
* Fix getting current user failing on Windows when no profile directory is present. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 
* Size the in-flight event budget for the Elasticsearch exporter&#39;s concurrency in OTel mode. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 

  For Beats in the otel runtime (the default), the Elasticsearch output now runs two exporter consumers per connection and
  sizes `queue.mem.events` against that consumer count rather than the output&#39;s configured
  worker count. The performance preset budgets are sized for the process runtime, which holds
  un-acknowledged events in fewer places, so the OTel runtime ran short of in-flight events and
  left the connection idle waiting on Elasticsearch. The `balanced`, `scale` and `latency`
  presets roughly double their event rate as a result, at an unchanged connection count.
  
* Stop Fleet Server containers from re-enrolling on every restart. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) [#15922](https://github.com/elastic/elastic-agent/issues/15922)

  A container started with FLEET_SERVER_ENABLE=1 and a persisted state directory
  enrolled again on every restart, leaving an offline agent record in Fleet each
  time. The restart check compared the persisted Fleet host against FLEET_URL,
  which is not used in this topology, so it never matched. The check now compares
  against the Fleet Server internal endpoint that enrollment actually persists.
  Additionally, a failure to reach Fleet Server while validating the stored API
  key no longer aborts startup or discards the enrollment; only a revoked API key
  triggers a re-enrollment.
  
* Exclude elastic-agent-metrics.ndjson file from log ingestion. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 
* Fix Windows FIPS upgrade failure caused by mismatched directory name. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 
* Inputs running in OTel runtime with kafka output and Kerberos authentication enabled will now fallback to process runtime. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 
* Allow the current Windows Agent user to write component executables. [#16220](https://github.com/elastic/elastic-agent/pull/16220) [#16235](https://github.com/elastic/elastic-agent/pull/16235) [#16237](https://github.com/elastic/elastic-agent/pull/16237) 

