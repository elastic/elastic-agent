## 9.3.8 [elastic-agent-release-notes-9.3.8]



### Features and enhancements [elastic-agent-9.3.8-features-enhancements]


* Update OTel Collector components to v0.155.0. [#15414](https://github.com/elastic/elastic-agent/pull/15414) 


### Fixes [elastic-agent-9.3.8-fixes]


* Redact sensitive HTTP header values embedded in Fleet environment variables in diagnostics archives. [#15284](https://github.com/elastic/elastic-agent/pull/15284)
* Fix duplicate entries, empty unit dirs, and EDOT error handling in OTel diagnostics. [#15108](https://github.com/elastic/elastic-agent/pull/15108)
* Preserve locally-configured `monitoring.http.host` across Fleet policy check-ins. [#15291](https://github.com/elastic/elastic-agent/pull/15291)
* Fix "failed to unmarshal checkin actions" error on idle Fleet check-ins. [#15398](https://github.com/elastic/elastic-agent/pull/15398) [#15397](https://github.com/elastic/elastic-agent/issues/15397)
* Override `fleet.ssl.certificate_authorities` from environment variables in container mode. [#15427](https://github.com/elastic/elastic-agent/pull/15427) 

