## 9.2.2 [elastic-agent-release-notes-9.2.2]





### Fixes [elastic-agent-9.2.2-fixes]


* Redact secrets in slices. [#11271](https://github.com/elastic/elastic-agent/pull/11271) 

  Redact secrets in conifg and component files found in the diagnostics archive that occur within slices.
* Fix filesource provider to work with kubernetes secret mounts. [#11050](https://github.com/elastic/elastic-agent/pull/11050)
* Ensure the monitoring input for the OTel collector can only run inside the collector. [#11204](https://github.com/elastic/elastic-agent/pull/11204) 
* Fix a fatal startup error in Beats Receivers caused by truncation of long UTF-8 hostnames. [#11285](https://github.com/elastic/elastic-agent/pull/11285)
* Allow host to be a string for otel configuration translation. [#11394](https://github.com/elastic/elastic-agent/pull/11394) [#11352](https://github.com/elastic/elastic-agent/issues/11352)

