## 9.3.5 [elastic-agent-release-notes-9.3.5]



### Features and enhancements [elastic-agent-9.3.5-features-enhancements]


* Add Azure Monitor receiver to EDOT Collector. [#12919](https://github.com/elastic/elastic-agent/pull/12919) 
* Add Azure encoding extension to EDOT Collector. [#13583](https://github.com/elastic/elastic-agent/pull/13583) 
* Update Go to v1.26.2. [#13683](https://github.com/elastic/elastic-agent/pull/13683) 
* Update OTel Collector components to v0.150.0. [#14104](https://github.com/elastic/elastic-agent/pull/14104) 
* Update OTel Collector components to v1.58.0/v0.152.0. [#14326](https://github.com/elastic/elastic-agent/pull/14326) 


### Fixes [elastic-agent-9.3.5-fixes]


* Upgrade npm to v11 in non-wolfi `elastic-agent-complete` Docker images. [#14167](https://github.com/elastic/elastic-agent/pull/14167) 
* Fix `rpm --prefix` installation service file not being found after reboot. [#13284](https://github.com/elastic/elastic-agent/pull/13284) 
* Make enrollment retry backoff respect context cancellation. [#13698](https://github.com/elastic/elastic-agent/pull/13698)
* Clean up leftover artifacts when `elastic-agent install` fails. [#13705](https://github.com/elastic/elastic-agent/pull/13705) 
* Stop MIGRATE action from inheriting the source cluster's Fleet configuration. [#13756](https://github.com/elastic/elastic-agent/pull/13756) 
* Report policy ID and revision in checkin when policy change acknowledgements are disabled. [#13938](https://github.com/elastic/elastic-agent/pull/13938) [#264983](https://github.com/elastic/kibana/issues/264983)
* Fix handling of console events on Windows. [#13862](https://github.com/elastic/elastic-agent/pull/13862) [#13586](https://github.com/elastic/elastic-agent/issues/13586)
* Retry delayed enrollment on invalid token instead of failing fast. [#13861](https://github.com/elastic/elastic-agent/pull/13861) 
* Stop the Windows service promptly during enrollment retries. [#13878](https://github.com/elastic/elastic-agent/pull/13878) 
* Fix profiling agent DaemonSet deployment on Kubernetes v1.33+. [#13894](https://github.com/elastic/elastic-agent/pull/13894) 
* Clamp non-positive `agent.download.retry_sleep_init_duration` values to the default of `30s` to prevent download retry storms. [#13974](https://github.com/elastic/elastic-agent/pull/13974) 
* Redact sensitive values in slice maps. [#14007](https://github.com/elastic/elastic-agent/pull/14007) [#415](https://github.com/elastic/elastic-agent-libs/issues/415)
* Preserve unexpired available rollback agent versions during rollback. [#14024](https://github.com/elastic/elastic-agent/pull/14024) 
* Ship config samples, OTel collector spec, and endpoint resources zip without executable bits. [#14117](https://github.com/elastic/elastic-agent/pull/14117) [#13960](https://github.com/elastic/elastic-agent/issues/13960)
* Policy log level changes are applied after an agent restart. [#14078](https://github.com/elastic/elastic-agent/pull/14078) [#13196](https://github.com/elastic/elastic-agent/issues/13196)
* Correctly deduplicate privilege change actions on Linux. [#14114](https://github.com/elastic/elastic-agent/pull/14114) 
* Agent no longer fails to start when the upgrade marker file is corrupt. [#14194](https://github.com/elastic/elastic-agent/pull/14194) 
* Fix silent early-return when removing stale enrollment and upgrade artifacts. [#14234](https://github.com/elastic/elastic-agent/pull/14234) 
* Fix dangling symlink when rotating to a non-existent target. [#14238](https://github.com/elastic/elastic-agent/pull/14238) 
* Prevent upgrade watcher panic when grace period expires. [#14253](https://github.com/elastic/elastic-agent/pull/14253) 
* Notify endpoint-security before symlink swap, not before upgrade attempt. [#14397](https://github.com/elastic/elastic-agent/pull/14397) 
* Honour `--path.logs` when running `elastic-agent run`. [#14410](https://github.com/elastic/elastic-agent/pull/14410) [#13320](https://github.com/elastic/elastic-agent/issues/13320)

