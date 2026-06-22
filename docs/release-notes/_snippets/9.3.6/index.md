## 9.3.6 [elastic-agent-release-notes-9.3.6]



### Features and enhancements [elastic-agent-9.3.6-features-enhancements]


* Add health checks to EDOT collectors used in K8s Onboarding flow. [#14798](https://github.com/elastic/elastic-agent/pull/14798)

* Change bulk_response_filter_path in elasticsearch exporter configurations to match beats. [#14452](https://github.com/elastic/elastic-agent/pull/14452) [#12688](https://github.com/elastic/elastic-agent/issues/12688)
* Add Azure auth extension to EDOT Collector. [#14664](https://github.com/elastic/elastic-agent/pull/14664)
* Disable TLS certificate hot-reload by default. [#14598](https://github.com/elastic/elastic-agent/pull/14598)
* Update OTel Collector components to v0.153.0. [#14904](https://github.com/elastic/elastic-agent/pull/14904)


### Fixes [elastic-agent-9.3.6-fixes]


* Fix deprecated component name warnings in EDOT collector Helm values. [#14557](https://github.com/elastic/elastic-agent/pull/14557)

* Fix the bug where logging settings fail to apply in fleet-managed mode. [#14814](https://github.com/elastic/elastic-agent/pull/14814)
* Preserve live install during upgrade cleanup and report aborted upgrades to Fleet. [#14713](https://github.com/elastic/elastic-agent/pull/14713)
* Move fleet uninstall notification before installation directory removal as likely fix for runtime panic during uninstall on Windows. [#14581](https://github.com/elastic/elastic-agent/pull/14581) [#14142](https://github.com/elastic/elastic-agent/issues/14142)
* Read TLS config from environment variables in container mode. [#14649](https://github.com/elastic/elastic-agent/pull/14649)

  TLS certificate paths will now always be read from ELASTIC_AGENT_CERT and ELASTIC_AGENT_CERT_KEY in container mode rather than reading from potentially stale fleet.enc values.
* Fix container config override inconsistencies. [#14649](https://github.com/elastic/elastic-agent/pull/14649)

  Fixes a bug where container-mode overrides were correctly applied to the running agent but were overwritten by fleet.enc before being passed to the coordinator. This could result in incorrect config diagnostics and unnecessary restarts on policy updates.
* Fix accidental inclusion of cloud-defend in the Linux .tar.gz saving 151 MB of disk space. [#14771](https://github.com/elastic/elastic-agent/pull/14771)
* Fix bug where an empty request body could be sent after failing over to an alternate fleet host. [#14843](https://github.com/elastic/elastic-agent/pull/14843) [#14773](https://github.com/elastic/elastic-agent/issues/14773)
