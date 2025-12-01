## 9.1.8 [elastic-agent-release-notes-9.1.8]





### Fixes [elastic-agent-9.1.8-fixes]


* Redact secrets in slices. [#11271](https://github.com/elastic/elastic-agent/pull/11271) 

  Redact secrets in conifg and component files found in the diagnostics archive that occur within slices.
* Fix filesource provider to work with kubernetes secret mounts. [#11170](https://github.com/elastic/elastic-agent/pull/11170) [#11331](https://github.com/elastic/elastic-agent/pull/11331) [#11344](https://github.com/elastic/elastic-agent/pull/11344) [#11500](https://github.com/elastic/elastic-agent/pull/11500) [#11429](https://github.com/elastic/elastic-agent/pull/11429) [#467](https://github.com/elastic/elastic-agent/issues/467)
* Fix a fatal startup error in Beats Receivers caused by truncation of long UTF-8 hostnames. [#11170](https://github.com/elastic/elastic-agent/pull/11170) [#11331](https://github.com/elastic/elastic-agent/pull/11331) [#11344](https://github.com/elastic/elastic-agent/pull/11344) [#11500](https://github.com/elastic/elastic-agent/pull/11500) [#11429](https://github.com/elastic/elastic-agent/pull/11429) [#467](https://github.com/elastic/elastic-agent/issues/467)

