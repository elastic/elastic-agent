## 9.2.1 [elastic-agent-release-notes-9.2.1]



### Features and enhancements [elastic-agent-9.2.1-features-enhancements]


* Add sample config files for Windows ES and mOTLP ingestion. [#10728](https://github.com/elastic/elastic-agent/pull/10728) [#10540](https://github.com/elastic/elastic-agent/issues/10540)


### Fixes [elastic-agent-9.2.1-fixes]


* Reduce memory usage by executing Elastic Agent self-monitoring inputs as OpenTelemetry collector receivers by default. [#10594](https://github.com/elastic/elastic-agent/pull/10594) 

  Self-monitoring inputs which were previously executed as Beat sub-processes are now executed as receivers in a single OpenTelemetry collector sub-process.
  For a Fleet managed Elastic Agent running the default System integration, steady state memory usage is reduced by 11.5% (79.1 MB) on Linux, 34.5% (185.77 MB) on Windows, and 23.0% (115.9 MB) on MacOS.
  This is the first phase of work reducing the Elastic Agent&#39;s memory footprint, memory reductions will continue in future releases.
  
* Fix issue where switching to OTEL runtime would cause data to be re-ingested. [#10857](https://github.com/elastic/elastic-agent/pull/10857) 
* Fix signal handling for the EDOT Collector. [#10908](https://github.com/elastic/elastic-agent/pull/10908) 
* Reload agent binary source settings as configured in Fleet. [#10993](https://github.com/elastic/elastic-agent/pull/10993) 

