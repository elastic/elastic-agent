## 9.3.8 [elastic-agent-release-notes-9.3.8]



### Features and enhancements [elastic-agent-9.3.8-features-enhancements]


* Update OTel Collector components to v0.155.0. [#15414](https://github.com/elastic/elastic-agent/pull/15414) 


### Fixes [elastic-agent-9.3.8-fixes]


* Redact sensitive HTTP header values embedded in Fleet env vars in diagnostics archives. [#15284](https://github.com/elastic/elastic-agent/pull/15284) 

  Diagnostics archives could expose authentication tokens when Fleet header environment
  variables (such as FLEET_HEADER, FLEET_HEADERS, FLEET_KIBANA_HEADER, and
  FLEET_KIBANA_HEADERS) contained sensitive HTTP header values. The diagnostics redaction
  logic now expands and redacts individual header values within these variables.
  
* Fix duplicate entries, empty unit dirs, and EDOT error handling in OTel diagnostics. [#15108](https://github.com/elastic/elastic-agent/pull/15108) 

  The OTel diagnostics ZIP no longer contains duplicate entries and no longer creates empty unit subdirectories. Components with no EDOT diagnostics no longer produce a spurious error in the archive. Also, an unexpected EDOT error used to abort the whole component-diagnostics request; now it is recorded per component so the diagnostics archive is still produced.
  
* Preserve locally-configured monitoring.http.host across Fleet policy check-ins. [#15291](https://github.com/elastic/elastic-agent/pull/15291) 

  A regression introduced in 9.4.2 caused the agent&#39;s monitoring HTTP listener to rebind to the
  default host (localhost) on every Fleet policy check-in, discarding any host configured locally
  via agent.monitoring.http.host (e.g. 0.0.0.0). The policy-change handler now only applies
  monitoring.http/pprof settings from the policy when they are explicitly present, leaving the
  locally-configured values untouched otherwise.
  
* Fix spurious &#34;failed to unmarshal checkin actions&#34; error on idle Fleet check-ins. [#15398](https://github.com/elastic/elastic-agent/pull/15398) [#15397](https://github.com/elastic/elastic-agent/issues/15397)
* Override fleet.ssl.certificate_authorities from env vars in container mode. [#15427](https://github.com/elastic/elastic-agent/pull/15427) 

