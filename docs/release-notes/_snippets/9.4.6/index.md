## 9.4.6 [elastic-agent-release-notes-9.4.6]



### Features and enhancements [elastic-agent-9.4.6-features-enhancements]


* Bump github.com/kardianos/service to v1.3.0 and update Linux systemd template for new mini template engine. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) 
* Update Go to 1.26.6. [#16203](https://github.com/elastic/elastic-agent/pull/16203) 


### Fixes [elastic-agent-9.4.6-fixes]


* Fix local privilege escalation via binary tampering on Windows unprivileged installs. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) 
* Stop Fleet Server containers from re-enrolling on every restart. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) [#15922](https://github.com/elastic/elastic-agent/issues/15922)

  A container started with FLEET_SERVER_ENABLE=1 and a persisted state directory
  enrolled again on every restart, leaving an offline agent record in Fleet each
  time. The restart check compared the persisted Fleet host against FLEET_URL,
  which is not used in this topology, so it never matched. The check now compares
  against the Fleet Server internal endpoint that enrollment actually persists.
  Additionally, a failure to reach Fleet Server while validating the stored API
  key no longer aborts startup or discards the enrollment; only a revoked API key
  triggers a re-enrollment.
  
* Fix Windows FIPS upgrade failure caused by mismatched directory name. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) 
* Align OTel Elasticsearch exporter request and document retry behavior with Beats Elasticsearch output. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) [#14531](https://github.com/elastic/elastic-agent/issues/14531)
* Inputs running in OTel runtime with kafka output and Kerberos authentication enabled will now fallback to process runtime. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) 
* Allow the current Windows Agent user to write component executables. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) 
* Diagnostics now collects component trace logs in container deployments. [#16348](https://github.com/elastic/elastic-agent/pull/16348) [#16357](https://github.com/elastic/elastic-agent/pull/16357) [#16188](https://github.com/elastic/elastic-agent/pull/16188) 

