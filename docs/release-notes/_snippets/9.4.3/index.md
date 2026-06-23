## 9.4.3 [elastic-agent-release-notes-9.4.3]



### Features and enhancements [elastic-agent-9.4.3-features-enhancements]


* Add health checks to EDOT collectors used in K8s Onboarding flow.  

* Add Azure Monitor receiver to EDOT Collector.  
* Change bulk_response_filter_path in elasticsearch exporter configurations to match beats. [#14452](https://github.com/elastic/elastic-agent/pull/14452) [#12688](https://github.com/elastic/elastic-agent/issues/12688)
* Add Azure auth extension to EDOT Collector.  
* Disable TLS certificate hot-reload by default.  
* Adds system.cpu.cores field to self monitoring data. [#14885](https://github.com/elastic/elastic-agent/pull/14885) [#14862](https://github.com/elastic/elastic-agent/issues/14862)


### Fixes [elastic-agent-9.4.3-fixes]


* Fix deprecated component name warnings in EDOT collector Helm values.  

* Fix the bug where logging settings fail to apply in fleet-managed mode.  
* Preserve live install during upgrade cleanup and report aborted upgrades to Fleet.  
* Remove the github.com/twmb/franz-go dependency to shrink elastic-agent binary size by ~7 MB. [#14533](https://github.com/elastic/elastic-agent/pull/14533) 
* Move fleet uninstall notification before installation directory removal as likely fix for runtime panic during uninstall on Windows. [#14581](https://github.com/elastic/elastic-agent/pull/14581) [#14142](https://github.com/elastic/elastic-agent/issues/14142)
* Read TLS config from environment variables in container mode.  

  TLS certificate paths will now always be read from ELASTIC_AGENT_CERT and ELASTIC_AGENT_CERT_KEY in container mode rather than reading from potentially stale fleet.enc values.
* Fix container config override inconsistencies.  

  Fixes a bug where container-mode overrides were correctly applied to the running agent but were overwritten by fleet.enc before being passed to the coordinator. This could result in incorrect config diagnostics and unnecessary restarts on policy updates.
* Fix accidental inclusion of cloud-defend in the Linux .tar.gz saving 151 MB of disk space.  
* Ignore late component check-ins after a command runtime has stopped.  [#14298](https://github.com/elastic/elastic-agent/issues/14298)
* Fix Windows upgrade hang caused by an infinite loop scanning the Uninstall registry key.  [#14764](https://github.com/elastic/elastic-agent/issues/14764)

  FindMSIProductCodes used registry.Key.ReadSubKeyNames(100) in a loop that only
  exited on a non-nil error. That call does not paginate and returns a nil error
  whenever the Uninstall key has at least 100 subkeys, so on Windows hosts with
  100 or more Add/Remove Programs entries the agent spun forever during startup
  when upgrading from a pre-9.4.0 version, causing the upgrade watcher to roll
  back. The function now reads all subkey names in a single call.
  
* Fix bug where an empty request body could be sent after failing over to an alternate fleet host.  [#14773](https://github.com/elastic/elastic-agent/issues/14773)

