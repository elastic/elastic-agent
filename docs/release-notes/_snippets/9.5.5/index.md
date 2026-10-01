## 9.5.5 [elastic-agent-release-notes-9.5.5]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.5.5-breaking-changes)._


### Features and enhancements [elastic-agent-9.5.5-features-enhancements]


* Add regression test for Kubernetes metrics RBAC deadlock (#15666). [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) [#15666](https://github.com/elastic/elastic-agent/issues/15666)
* Support the EDOT Collector kube-stack Helm chart on OpenShift. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 

  The new `kube-stack/openshift/values.yaml` file grants the minimum permissions
  and the security settings that the EDOT Collector opentelemetry-kube-stack
  requires to run on OpenShift. Apply it on top of the Kubernetes values file
  (default or managed OTLP).
  
* Allow overriding Elastic Agent hostname via ELASTIC_AGENT_HOSTNAME environment variable. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Add enqueue_failed metrics to elasticmonitoringprocessor dropped count. [#16420](https://github.com/elastic/elastic-agent/pull/16420) 
* Update Go to 1.26.8. [#16490](https://github.com/elastic/elastic-agent/pull/16490) 
* Enable kafka exporter and receiver in FIPS builds. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Update OTel Collector components to v0.161.0. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Support initial lookback for AWS CloudWatch logs in the EDOT Collector. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Do not install manpages and docs in docker image. [#16763](https://github.com/elastic/elastic-agent/pull/16763) 
* Run the EDOT daemon collector as non-root on OpenShift. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 

  The new `kube-stack/openshift/rootless-values.yaml` file runs the daemon
  collector as non-root. An init container makes the filelog checkpoint
  directory on the node writable by the collector.
  


### Fixes [elastic-agent-9.5.5-fixes]


* Fix temporary Fleet Server HTTP codes 429 and 503 from failing an upgrade. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Revert non-ironbank container images to ubi9. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Fix diagnostics for otel components containing `/`. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 

  Components containing `/` in id or stream-id has been skipped from diagnostics
* Keep per-stream OTel diagnostics unique in the diagnostics archive. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) [#16287](https://github.com/elastic/elastic-agent/issues/16287)
* Fix Ironbank Dockerfile to restore module yml file permissions to 0644 after broad 0666 chmod. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Fix propagation of custom namespace for osquerybeat. [#16624](https://github.com/elastic/elastic-agent/pull/16624) [#16609](https://github.com/elastic/elastic-agent/issues/16609)
* Removes unneeded Temporary Resource ID. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Drop unnecessary self-monitoring data points. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Fix unnecessary agent.download.retry_sleep_init_duration warning log on every policy change. [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16781](https://github.com/elastic/elastic-agent/pull/16781) [#16901](https://github.com/elastic/elastic-agent/pull/16901) [#16938](https://github.com/elastic/elastic-agent/pull/16938) [#16937](https://github.com/elastic/elastic-agent/pull/16937) 

