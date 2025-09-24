## 9.1.3 [elastic-agent-release-notes-9.1.3]


### Features and enhancements [elastic-agent-9.1.3-features-enhancements]

* Adjust the timeout for Elastic Defend check command. [#9329](https://github.com/elastic/elastic-agent/pull/9329) [#9521](https://github.com/elastic/elastic-agent/pull/9521) [#9522](https://github.com/elastic/elastic-agent/pull/9522) [#9545](https://github.com/elastic/elastic-agent/pull/9545) [#9213](https://github.com/elastic/elastic-agent/pull/9213) 
* Update OTel components to v0.130.0. [#9329](https://github.com/elastic/elastic-agent/pull/9329) [#9521](https://github.com/elastic/elastic-agent/pull/9521) [#9522](https://github.com/elastic/elastic-agent/pull/9522) [#9545](https://github.com/elastic/elastic-agent/pull/9545) [#9362](https://github.com/elastic/elastic-agent/pull/9362) 


### Fixes [elastic-agent-9.1.3-fixes]

* Upgrade to Go 1.24.6. [#9287](https://github.com/elastic/elastic-agent/pull/9287) 
* On Windows, retry saving the Agent information file to disk. [#9224](https://github.com/elastic/elastic-agent/pull/9224) [#5862](https://github.com/elastic/elastic-agent/issues/5862)

  Saving the Agent information file involves renaming/moving a file to its final destination. However, on Windows, it is sometimes not possible to rename/move a file to its destination file because the destination file is locked by another process (e.g. antivirus software). For such situations, we now retry the save operation on Windows.
  
* Correct hints annotations parsing to resolve only `${kubernetes.*}` placeholders instead of resolving all `${...}` patterns. [#9307](https://github.com/elastic/elastic-agent/pull/9307) 
* Treat exit code 28 from Endpoint binary as non-fatal. [#9320](https://github.com/elastic/elastic-agent/pull/9320) 
* Fixed jitter backoff strategy reset. [#9342](https://github.com/elastic/elastic-agent/pull/9342) [#8864](https://github.com/elastic/elastic-agent/issues/8864)
* Fix Docker container failing to start with no matching vars: ${env.ELASTICSEARCH_API_KEY:} and similar errors by restoring support for `:` to set default values. [#9451](https://github.com/elastic/elastic-agent/pull/9451) [#9328](https://github.com/elastic/elastic-agent/issues/9328)
* Fix deb upgrade by stopping elastic-agent service before stopping endpoint. [#9462](https://github.com/elastic/elastic-agent/pull/9462) 

