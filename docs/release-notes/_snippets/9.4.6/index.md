## 9.4.6 [elastic-agent-release-notes-9.4.6]

::::{important} 
The 9.4.6 release contains fixes for potential security vulnerabilities. For details, go to [security announcements](https://discuss.elastic.co/c/announcements/security-announcements/31).
::::

### Features and enhancements [elastic-agent-9.4.6-features-enhancements]


* Bump `github.com/kardianos/service` to v1.3.0 and update Linux `systemd` template for new mini template engine. [#16047](https://github.com/elastic/elastic-agent/pull/16047) 

### Fixes [elastic-agent-9.4.6-fixes]


* Fix local privilege escalation via binary tampering on Windows unprivileged installs. [#16154](https://github.com/elastic/elastic-agent/pull/16154) 
* Stop Fleet Server containers from re-enrolling on every restart. [#16019](https://github.com/elastic/elastic-agent/pull/16019) [#15922](https://github.com/elastic/elastic-agent/issues/15922)
* Fix Windows FIPS upgrade failure caused by mismatched directory name. [#16087](https://github.com/elastic/elastic-agent/pull/16087) 
* Align OTel Elasticsearch exporter request and document retry behavior with Beats Elasticsearch output. [#16303](https://github.com/elastic/elastic-agent/pull/16303) [#14531](https://github.com/elastic/elastic-agent/issues/14531)
* Inputs running in OTel runtime with Kafka output and Kerberos authentication enabled will now fallback to process runtime. [#16144](https://github.com/elastic/elastic-agent/pull/16144) 
* Allow the current Windows Agent user to write component executables. [#16176](https://github.com/elastic/elastic-agent/pull/16176) 
* Diagnostics now collects component trace logs in container deployments. [#16249](https://github.com/elastic/elastic-agent/pull/16249) 
