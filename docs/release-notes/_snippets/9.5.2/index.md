## 9.5.2 [elastic-agent-release-notes-9.5.2]



### Features and enhancements [elastic-agent-9.5.2-features-enhancements]


* Bump `github.com/kardianos/service` to v1.3.0 and update Linux `systemd` template for new mini template engine. [#16046](https://github.com/elastic/elastic-agent/pull/16046) 
* Update Go to 1.26.6. [#16203](https://github.com/elastic/elastic-agent/pull/16203) 


### Fixes [elastic-agent-9.5.2-fixes]


* Fix local privilege escalation via binary tampering on Windows unprivileged installs. [#16153](https://github.com/elastic/elastic-agent/pull/16153) 
* Fix getting current user failing on Windows when no profile directory is present. [#16005](https://github.com/elastic/elastic-agent/pull/16005) 
* Size the in-flight event budget for the Elasticsearch exporter's concurrency in OTel mode. [#16204](https://github.com/elastic/elastic-agent/pull/16204)
* Stop Fleet Server containers from re-enrolling on every restart. [#16020](https://github.com/elastic/elastic-agent/pull/16020) [#15922](https://github.com/elastic/elastic-agent/issues/15922)
* Exclude `elastic-agent-metrics.ndjson` file from log ingestion. [#16084](https://github.com/elastic/elastic-agent/pull/16084) 
* Fix Windows FIPS upgrade failure caused by a mismatched directory name. [#16086](https://github.com/elastic/elastic-agent/pull/16086) 
* Inputs running in OTel runtime with the Kafka output and Kerberos authentication enabled now fallback to process runtime. [#16165](https://github.com/elastic/elastic-agent/pull/16165) 
* Allow the current Windows Agent user to write component executables. [#16175](https://github.com/elastic/elastic-agent/pull/16175) 

