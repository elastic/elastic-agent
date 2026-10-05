## 9.5.5 [elastic-agent-release-notes-9.5.5]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.5.5-breaking-changes)._


### Features and enhancements [elastic-agent-9.5.5-features-enhancements]


* Add regression test for Kubernetes metrics RBAC deadlock. [#15900](https://github.com/elastic/elastic-agent/pull/15900) [#15666](https://github.com/elastic/elastic-agent/issues/15666)
* Support the kube-stack Helm chart on OpenShift for Elastic Agent configured as an OTel Collector. The new `kube-stack/openshift/values.yaml` file grants the minimum permissions and security settings required to run on OpenShift. Apply it on top of the Kubernetes values file (default or managed OTLP). [#16524](https://github.com/elastic/elastic-agent/pull/16524)
* Allow overriding the Elastic Agent hostname via the `ELASTIC_AGENT_HOSTNAME` environment variable. [#15686](https://github.com/elastic/elastic-agent/pull/15686) 
* Add `enqueue_failed` metrics to `elasticmonitoringprocessor` dropped count. [#16420](https://github.com/elastic/elastic-agent/pull/16420) 
* Update Go to 1.26.8. [#16490](https://github.com/elastic/elastic-agent/pull/16490) 
* Enable the Kafka exporter and receiver in FIPS builds. [#16691](https://github.com/elastic/elastic-agent/pull/16691) 
* Update OTel Collector components to v0.161.0. [#16745](https://github.com/elastic/elastic-agent/pull/16745) 
* Support initial lookback for AWS CloudWatch logs in Elastic Agent configured as an OTel Collector. [#16745](https://github.com/elastic/elastic-agent/pull/16745) 
* Do not install manpages and docs in Docker image. [#16763](https://github.com/elastic/elastic-agent/pull/16763) 
* Run the kube-stack daemon collector as non-root on OpenShift for Elastic Agent configured as an OTel Collector. [#16837](https://github.com/elastic/elastic-agent/pull/16837)


### Fixes [elastic-agent-9.5.5-fixes]


* Fix temporary Fleet Server HTTP codes 429 and 503 from failing an upgrade. [#15934](https://github.com/elastic/elastic-agent/pull/15934) 
* Revert non-Ironbank container images to UBI9. [#16396](https://github.com/elastic/elastic-agent/pull/16396) 
* Fix diagnostics for OTel components containing `/`. [#16453](https://github.com/elastic/elastic-agent/pull/16453)
* Keep per-stream OTel diagnostics unique in the diagnostics archive. [#16459](https://github.com/elastic/elastic-agent/pull/16459) [#16287](https://github.com/elastic/elastic-agent/issues/16287)
* Fix the Ironbank Dockerfile to restore module YML file permissions to `0644` after a broad `chmod 0666`. [#16565](https://github.com/elastic/elastic-agent/pull/16565) 
* Fix propagation of custom namespace for Osquerybeat. [#16624](https://github.com/elastic/elastic-agent/pull/16624) [#16609](https://github.com/elastic/elastic-agent/issues/16609)
* Removes unneeded Temporary Resource ID. [#16792](https://github.com/elastic/elastic-agent/pull/16792) 
* Drop unnecessary self-monitoring data points. [#16805](https://github.com/elastic/elastic-agent/pull/16805) 
* Fix unnecessary `agent.download.retry_sleep_init_duration` warning log on every policy change. [#16819](https://github.com/elastic/elastic-agent/pull/16819) 

