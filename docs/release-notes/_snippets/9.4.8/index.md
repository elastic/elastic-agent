## 9.4.8 [elastic-agent-release-notes-9.4.8]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.4.8-breaking-changes)._


### Features and enhancements [elastic-agent-9.4.8-features-enhancements]


* Add regression test for Kubernetes metrics RBAC deadlock (#15666). [#15900](https://github.com/elastic/elastic-agent/pull/15900) [#15666](https://github.com/elastic/elastic-agent/issues/15666)
* Allow overriding Elastic Agent hostname via ELASTIC_AGENT_HOSTNAME environment variable. [#15686](https://github.com/elastic/elastic-agent/pull/15686) 
* Update Go to 1.26.8. [#16490](https://github.com/elastic/elastic-agent/pull/16490) 
* Update OTel Collector components to v0.161.0. [#16745](https://github.com/elastic/elastic-agent/pull/16745) 
* Do not install manpages and docs in docker image. [#16763](https://github.com/elastic/elastic-agent/pull/16763) 


### Fixes [elastic-agent-9.4.8-fixes]


* Fix temporary Fleet Server HTTP codes 429 and 503 from failing an upgrade. [#15934](https://github.com/elastic/elastic-agent/pull/15934) 
* Revert non-ironbank container images to ubi9. [#16396](https://github.com/elastic/elastic-agent/pull/16396) 
* Fix diagnostics for otel components containing `/`. [#16453](https://github.com/elastic/elastic-agent/pull/16453) 

  Components containing `/` in id or stream-id has been skipped from diagnostics
* Fix Ironbank Dockerfile to restore module yml file permissions to 0644 after broad 0666 chmod. [#16565](https://github.com/elastic/elastic-agent/pull/16565) 
* Fix unnecessary agent.download.retry_sleep_init_duration warning log on every policy change. [#16819](https://github.com/elastic/elastic-agent/pull/16819) 

