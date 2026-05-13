## 9.4.1 [elastic-agent-release-notes-9.4.1]



### Features and enhancements [elastic-agent-9.4.1-features-enhancements]


* Update Go version to v1.26.2. [#13683](https://github.com/elastic/elastic-agent/pull/13683) 


### Fixes [elastic-agent-9.4.1-fixes]


* Exit gracefully when {{agent}} receives a console control event such as CTRL+C or CTRL+BREAK on Windows. [#13862](https://github.com/elastic/elastic-agent/pull/13862) [#13586](https://github.com/elastic/elastic-agent/issues/13586)
* Stop the Windows service promptly during enrollment retries. [#13878](https://github.com/elastic/elastic-agent/pull/13878) 
* Fix profiling agent DaemonSet deployment on Kubernetes v1.33+. [#13894](https://github.com/elastic/elastic-agent/pull/13894)
* Clamp non-positive `agent.download.retry_sleep_init_duration` values to the default of `30s` to prevent download retry storms. [#13974](https://github.com/elastic/elastic-agent/pull/13974)
* Preserve unexpired available rollback agent versions during a rollback. [#14024](https://github.com/elastic/elastic-agent/pull/14024) [#14021](https://github.com/elastic/elastic-agent/issues/14021)

