## 9.3.6 [elastic-agent-release-notes-9.3.6]



### Features and enhancements [elastic-agent-9.3.6-features-enhancements]


* Add health checks to EDOT Collectors used in the Kubernetes onboarding flow. [#14798](https://github.com/elastic/elastic-agent/pull/14798)
* Change `bulk_response_filter_path` in elasticsearch exporter configurations to match beats. [#14452](https://github.com/elastic/elastic-agent/pull/14452) [#12688](https://github.com/elastic/elastic-agent/issues/12688)
* Add Azure auth extension to EDOT Collector. [#14664](https://github.com/elastic/elastic-agent/pull/14664)
* Disable TLS certificate hot-reload by default. [#14598](https://github.com/elastic/elastic-agent/pull/14598)
* Update OTel Collector components to v0.153.0. [#14904](https://github.com/elastic/elastic-agent/pull/14904)


### Fixes [elastic-agent-9.3.6-fixes]


* Fix deprecated component name warnings in EDOT Collector Helm values. [#14557](https://github.com/elastic/elastic-agent/pull/14557)
* Fix a bug where logging settings failed to apply in Fleet-managed mode. [#14814](https://github.com/elastic/elastic-agent/pull/14814)
* Preserve live install during upgrade cleanup and report aborted upgrades to Fleet. [#14713](https://github.com/elastic/elastic-agent/pull/14713)
* Notify Fleet of agent uninstall before marking the installation directory for removal. [#14581](https://github.com/elastic/elastic-agent/pull/14581) [#14142](https://github.com/elastic/elastic-agent/issues/14142)
* Read TLS config from environment variables in container mode. [#14649](https://github.com/elastic/elastic-agent/pull/14649)
* Fix container config override inconsistencies. [#14649](https://github.com/elastic/elastic-agent/pull/14649)
* Fix accidental inclusion of `cloud-defend` in the Linux `.tar.gz` package, saving 151 MB of disk space. [#14771](https://github.com/elastic/elastic-agent/pull/14771)
* Fix a bug where an empty request body could be sent after failing over to an alternate Fleet host. [#14843](https://github.com/elastic/elastic-agent/pull/14843) [#14773](https://github.com/elastic/elastic-agent/issues/14773)
