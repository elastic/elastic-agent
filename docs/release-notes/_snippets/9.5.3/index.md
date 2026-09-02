## 9.5.3 [elastic-agent-release-notes-9.5.3]



### Features and enhancements [elastic-agent-9.5.3-features-enhancements]


* Make the dynamic inputs runtime override configurable per beat, input type and variable. [#16347](https://github.com/elastic/elastic-agent/pull/16347) [#16421](https://github.com/elastic/elastic-agent/pull/16421) [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16409](https://github.com/elastic/elastic-agent/pull/16409) [#16436](https://github.com/elastic/elastic-agent/pull/16436) [#16460](https://github.com/elastic/elastic-agent/pull/16460) [#16461](https://github.com/elastic/elastic-agent/pull/16461) 

  `agent.internal.runtime.dynamic_inputs` now accepts a map in addition to the existing
  runtime name, allowing the runtime used by components with dynamic inputs to be set per
  beat and per input type. It also accepts a `static_variables` list of dynamic provider
  variables that cannot change at runtime; an input resolving only such variables is no
  longer treated as dynamic.
  
* Reduce the size of osquery.app on macOS by 75% by stripping the unused architecture slice. [#16347](https://github.com/elastic/elastic-agent/pull/16347) [#16421](https://github.com/elastic/elastic-agent/pull/16421) [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16409](https://github.com/elastic/elastic-agent/pull/16409) [#16436](https://github.com/elastic/elastic-agent/pull/16436) [#16460](https://github.com/elastic/elastic-agent/pull/16460) [#16461](https://github.com/elastic/elastic-agent/pull/16461) 


### Fixes [elastic-agent-9.5.3-fixes]


* Align OTel Elasticsearch exporter request and document retry behavior with Beats Elasticsearch output. [#16347](https://github.com/elastic/elastic-agent/pull/16347) [#16421](https://github.com/elastic/elastic-agent/pull/16421) [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16409](https://github.com/elastic/elastic-agent/pull/16409) [#16436](https://github.com/elastic/elastic-agent/pull/16436) [#16460](https://github.com/elastic/elastic-agent/pull/16460) [#16461](https://github.com/elastic/elastic-agent/pull/16461) [#14531](https://github.com/elastic/elastic-agent/issues/14531)
* Diagnostics now collects component trace logs in container deployments. [#16347](https://github.com/elastic/elastic-agent/pull/16347) [#16421](https://github.com/elastic/elastic-agent/pull/16421) [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16409](https://github.com/elastic/elastic-agent/pull/16409) [#16436](https://github.com/elastic/elastic-agent/pull/16436) [#16460](https://github.com/elastic/elastic-agent/pull/16460) [#16461](https://github.com/elastic/elastic-agent/pull/16461) 
* Fix Kafka lz4/snappy compression failing in the OTel runtime after 9.5. [#16347](https://github.com/elastic/elastic-agent/pull/16347) [#16421](https://github.com/elastic/elastic-agent/pull/16421) [#16422](https://github.com/elastic/elastic-agent/pull/16422) [#16409](https://github.com/elastic/elastic-agent/pull/16409) [#16436](https://github.com/elastic/elastic-agent/pull/16436) [#16460](https://github.com/elastic/elastic-agent/pull/16460) [#16461](https://github.com/elastic/elastic-agent/pull/16461) [#16239](https://github.com/elastic/elastic-agent/issues/16239)

