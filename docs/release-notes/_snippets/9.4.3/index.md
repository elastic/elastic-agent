## 9.4.3 [elastic-agent-release-notes-9.4.3]



### Features and enhancements [elastic-agent-9.4.3-features-enhancements]


* Add health checks to EDOT Collectors used in the Kubernetes onboarding flow.  
* Add Azure Monitor receiver to EDOT Collector.  
* Change `bulk_response_filter_path` in elasticsearch exporter configurations to match beats. [#14452](https://github.com/elastic/elastic-agent/pull/14452) [#12688](https://github.com/elastic/elastic-agent/issues/12688)
* Add Azure auth extension to EDOT Collector.  
* Disable TLS certificate hot-reload by default.  
* Add `system.cpu.cores` field to self-monitoring data. [#14885](https://github.com/elastic/elastic-agent/pull/14885) [#14862](https://github.com/elastic/elastic-agent/issues/14862)


### Fixes [elastic-agent-9.4.3-fixes]


* Fix deprecated component name warnings in EDOT Collector Helm values.  
* Fix a bug where logging settings failed to apply in Fleet-managed mode.  
* Preserve live install during upgrade cleanup and report aborted upgrades to Fleet.  
* Remove the `github.com/twmb/franz-go` dependency to shrink `elastic-agent` binary size by ~7 MB. [#14533](https://github.com/elastic/elastic-agent/pull/14533) 
* Notify Fleet of agent uninstall before marking the installation directory for removal. [#14581](https://github.com/elastic/elastic-agent/pull/14581) [#14142](https://github.com/elastic/elastic-agent/issues/14142)
* Read TLS config from environment variables in container mode.  
* Fix container config override inconsistencies.  
* Fix accidental inclusion of `cloud-defend` in the Linux `.tar.gz` package, saving 151 MB of disk space.  
* Ignore late component check-ins after a command runtime has stopped.  [#14298](https://github.com/elastic/elastic-agent/issues/14298)
* Fix Windows upgrade hang caused by an infinite loop scanning the Uninstall registry key.  [#14764](https://github.com/elastic/elastic-agent/issues/14764)
* Fix a bug where an empty request body could be sent after failing over to an alternate Fleet host.  [#14773](https://github.com/elastic/elastic-agent/issues/14773)

