## 9.4.9 [elastic-agent-release-notes-9.4.9]

::::{important} 
The 9.4.9 release contains fixes for potential security vulnerabilities. For details, go to [security announcements](https://discuss.elastic.co/c/announcements/security-announcements/31).
::::

### Features and enhancements [elastic-agent-9.4.9-features-enhancements]

* Enable the Kafka exporter and receiver in FIPS builds. [#16691](https://github.com/elastic/elastic-agent/pull/16691)
* Update Go to 1.26.9. [#17161](https://github.com/elastic/elastic-agent/pull/17161) 
* Update OTel Collector components to v0.163.0. [#17249](https://github.com/elastic/elastic-agent/pull/17249) 

### Fixes [elastic-agent-9.4.9-fixes]

* Bump npm to 12.2.1 and Node.js to 22.23.4 (24.22.1 on Wolfi) in the Elastic Agent complete Docker images to remove vulnerable `undici` copies. [#17359](https://github.com/elastic/elastic-agent/pull/17359)
* Remove the unneeded temporary resource ID field that AutoOps added to every document. [#16792](https://github.com/elastic/elastic-agent/pull/16792)
* Mark the `elastic-agent-wolfi-complete` image as complete. [#16841](https://github.com/elastic/elastic-agent/pull/16841)
* Fix an OTel Collector crash when all streams for a component are disabled. [#16900](https://github.com/elastic/elastic-agent/pull/16900)
* Fix a service runtime race that left Endpoint tamper-protected after an upgrade. [#16917](https://github.com/elastic/elastic-agent/pull/16917)
* Notify Endpoint of an upgrade before the symlink swap, even when the policy arrives after the upgrade action. [#16921](https://github.com/elastic/elastic-agent/pull/16921)
* Fix Elasticsearch output parameters sending all data to the first host when running Beats as OTel receivers. [#16937](https://github.com/elastic/elastic-agent/pull/16937)
* Fix variables in Fleet policy inputs and outputs being resolved too early outside of the main Elastic Agent process. [#16972](https://github.com/elastic/elastic-agent/pull/16972)
* Rebuild the Fleet client when only the TLS or CA settings change in a policy. [#17014](https://github.com/elastic/elastic-agent/pull/17014) [#17015](https://github.com/elastic/elastic-agent/issues/17015)
* Fix Elastic Agent configured as an OTel Collector hanging on shutdown when a component fails to start. [#17027](https://github.com/elastic/elastic-agent/pull/17027) [#16686](https://github.com/elastic/elastic-agent/issues/16686)
* Fix Elastic Agent retaining component states that no broadcaster subscriber can receive. [#17107](https://github.com/elastic/elastic-agent/pull/17107)
* Fix the Ironbank Dockerfile to restore the `elastic-otel-collector` execute permission (`0755`) after a broad `chmod 0666`. [#17118](https://github.com/elastic/elastic-agent/pull/17118)
* Fix the artifact downloader not using the Fleet Server URI for the PGP fallback. [#17256](https://github.com/elastic/elastic-agent/pull/17256) [#16700](https://github.com/elastic/elastic-agent/issues/16700)
* Increase the kube-stack cluster collector default memory limit to `256Mi`. [#17588](https://github.com/elastic/elastic-agent/pull/17588)
* Fix an OTel Collector startup delay caused by the Elasticsearch exporter version check. [#17598](https://github.com/elastic/elastic-agent/pull/17598) [#52437](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/52437)
