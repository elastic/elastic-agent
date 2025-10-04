## 9.0.8 [elastic-agent-release-notes-9.0.8]


### Features and enhancements [elastic-agent-9.0.8-features-enhancements]

* Agent cleans up downloads directory and the new versioned home if upgrade fails. [#9386](https://github.com/elastic/elastic-agent/pull/9386) [#5235](https://github.com/elastic/elastic-agent/issues/5235)
* When there is a disk space error during an upgrade, agent responds with clean insufficient disk space error message. [#9392](https://github.com/elastic/elastic-agent/pull/9392) [#5235](https://github.com/elastic/elastic-agent/issues/5235)


### Fixes [elastic-agent-9.0.8-fixes]

* Include aggregated agent status in HTTP liveness checks. [#9673](https://github.com/elastic/elastic-agent/pull/9673) [#9576](https://github.com/elastic/elastic-agent/issues/9576)
* Reduce-default-telemetry-frequency. [#9987](https://github.com/elastic/elastic-agent/pull/9987) 

  Reduce the default telemetry frequency to 60 seconds. This change aims to lower infrastructure costs and reduce label churn in time-series storage. High-cardinality labels sampled too frequently inflate storage and index size, and increase query latency with limited added value. Environments that require higher resolution can change the `collection_interval` for `hostmetrics`, `kubeletstats` and `k8s_cluster` receivers to a lower value.
* Fix stuck upgrade state by clearing coordinator overridden state after failed upgrade. [#9992](https://github.com/elastic/elastic-agent/pull/9992) 
* Include components units status in HTTP liveness checks. [#10060](https://github.com/elastic/elastic-agent/pull/10060) [#8047](https://github.com/elastic/elastic-agent/issues/8047)
* Add info about hostPID for Universal Profiling. [#10173](https://github.com/elastic/elastic-agent/pull/10173) 

