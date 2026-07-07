## 9.4.2 [elastic-agent-release-notes-9.4.2]



### Features and enhancements [elastic-agent-9.4.2-features-enhancements]


* Update OTel Collector components to v0.152.0. [#14323](https://github.com/elastic/elastic-agent/pull/14323) 


### Fixes [elastic-agent-9.4.2-fixes]


* Upgrade npm to v11 in non-wolfi `elastic-agent-complete` Docker images. [#14167](https://github.com/elastic/elastic-agent/pull/14167) 
* Report policy ID and revision in checkin when policy change acknowledgements are disabled. [#13938](https://github.com/elastic/elastic-agent/pull/13938) [#264983](https://github.com/elastic/kibana/issues/264983)
* Redact sensitive values in slice maps. [#14007](https://github.com/elastic/elastic-agent/pull/14007) [#415](https://github.com/elastic/elastic-agent-libs/issues/415)
* Ship config samples, OTel collector spec, and endpoint resources zip without executable bits. [#14117](https://github.com/elastic/elastic-agent/pull/14117) [#13960](https://github.com/elastic/elastic-agent/issues/13960)
* Policy log level changes are applied after an agent restart. [#14078](https://github.com/elastic/elastic-agent/pull/14078) [#13196](https://github.com/elastic/elastic-agent/issues/13196)
* Correctly deduplicate privilege change actions on Linux. [#14114](https://github.com/elastic/elastic-agent/pull/14114) 
* Agent no longer fails to start when the upgrade marker file is corrupt. [#14194](https://github.com/elastic/elastic-agent/pull/14194) 
* Fix silent early-return when removing stale enrollment and upgrade artifacts. [#14234](https://github.com/elastic/elastic-agent/pull/14234) 
* Fix dangling symlink when rotating to a non-existent target. [#14238](https://github.com/elastic/elastic-agent/pull/14238) 
* Prevent upgrade watcher panic when grace period expires. [#14253](https://github.com/elastic/elastic-agent/pull/14253) 
* Notify endpoint-security before symlink swap, not before upgrade attempt. [#14397](https://github.com/elastic/elastic-agent/pull/14397) 
* Honour `--path.logs` when running `elastic-agent run`. [#14410](https://github.com/elastic/elastic-agent/pull/14410) [#13320](https://github.com/elastic/elastic-agent/issues/13320)

