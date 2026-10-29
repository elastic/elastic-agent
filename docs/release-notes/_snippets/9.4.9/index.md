## 9.4.9 [elastic-agent-release-notes-9.4.9]

### Features and enhancements [elastic-agent-9.4.9-features-enhancements]

* Enable kafka exporter and receiver in FIPS builds. [#16691](https://github.com/elastic/elastic-agent/pull/16691) 
* Update Go to 1.26.9. [#17161](https://github.com/elastic/elastic-agent/pull/17161) 
* Update OTel Collector components to v0.163.0. [#17249](https://github.com/elastic/elastic-agent/pull/17249) 

### Fixes [elastic-agent-9.4.9-fixes]

* Bump npm to 12.2.1 and Node.js to 22.23.4 (24.22.1 on Wolfi) in the Elastic Agent complete Docker images to remove vulnerable undici copies. [#17359](https://github.com/elastic/elastic-agent/pull/17359) 
* Removes unneeded Temporary Resource ID. [#16792](https://github.com/elastic/elastic-agent/pull/16792) 
* Mark the elastic-agent-wolfi-complete image as complete. [#16841](https://github.com/elastic/elastic-agent/pull/16841) 
* Fix OTel collector crash when all streams for a component are disabled. [#16900](https://github.com/elastic/elastic-agent/pull/16900) 
* Fix service runtime race that left Endpoint tamper-protected after upgrade. [#16917](https://github.com/elastic/elastic-agent/pull/16917) 
* Notify Endpoint of upgrade before symlink swap even when policy arrives after the upgrade action. [#16921](https://github.com/elastic/elastic-agent/pull/16921) 
* Fix Elasticsearch output parameters sending all data to the first host when running beats as OTel receivers. [#16937](https://github.com/elastic/elastic-agent/pull/16937) 
* Fix variables in Fleet policy inputs and outputs being resolved too early outside of the main agent process. [#16972](https://github.com/elastic/elastic-agent/pull/16972) 
* Fleet client is rebuilt when only TLS/CA settings change in a policy. [#17014](https://github.com/elastic/elastic-agent/pull/17014) [#17015](https://github.com/elastic/elastic-agent/issues/17015)
* Fix EDOT collector hanging on shutdown when a component fails to start. [#17027](https://github.com/elastic/elastic-agent/pull/17027) [#16686](https://github.com/elastic/elastic-agent/issues/16686)
* Fix agent retaining component states that no broadcaster subscriber can receive. [#17107](https://github.com/elastic/elastic-agent/pull/17107) [#477](https://github.com/elastic/synthetics-dev/issues/477)
* Fix Ironbank Dockerfile to restore elastic-otel-collector execute permission (0755) after broad 0666 chmod. [#17118](https://github.com/elastic/elastic-agent/pull/17118) 
* Fix artifact downloader not using Fleet Server URI for PGP fallback. [#17256](https://github.com/elastic/elastic-agent/pull/17256) [#16700](https://github.com/elastic/elastic-agent/issues/16700)
* Increase kube-stack cluster collector default memory limit to 256Mi. [#17588](https://github.com/elastic/elastic-agent/pull/17588) 
* Fix OTel collector startup delay caused by the Elasticsearch exporter version check. [#17598](https://github.com/elastic/elastic-agent/pull/17598) [#52437](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/52437)
