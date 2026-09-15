## 9.5.3 [elastic-agent-release-notes-9.5.3]



### Features and enhancements [elastic-agent-9.5.3-features-enhancements]


* Make the dynamic inputs runtime override configurable per beat, input type and variable. [#16376](https://github.com/elastic/elastic-agent/pull/16376)
* Reduce the size of `osquery.app` on macOS by 75% by stripping the unused architecture slice. [#16263](https://github.com/elastic/elastic-agent/pull/16263) 


### Fixes [elastic-agent-9.5.3-fixes]


* Align OTel Elasticsearch exporter request and document retry behavior with Beats Elasticsearch output. [#16302](https://github.com/elastic/elastic-agent/pull/16302) [#14531](https://github.com/elastic/elastic-agent/issues/14531)
* Diagnostics now collects component trace logs in container deployments. [#16249](https://github.com/elastic/elastic-agent/pull/16249) 
* Fix Kafka `lz4/snappy` compression failing in the OTel runtime after 9.5. [#16372](https://github.com/elastic/elastic-agent/pull/16372) [#16239](https://github.com/elastic/elastic-agent/issues/16239)

