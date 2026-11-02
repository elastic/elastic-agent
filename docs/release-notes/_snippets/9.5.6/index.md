## 9.5.6 [elastic-agent-release-notes-9.5.6]

### Features and enhancements [elastic-agent-9.5.6-features-enhancements]

* Add OpenShift support to the Elastic Agent Helm chart. [#17112](https://github.com/elastic/elastic-agent/pull/17112)
* Add OpenShift support to the Elastic Agent standalone Kustomize manifests. [#17113](https://github.com/elastic/elastic-agent/pull/17113)
* Update Go to 1.26.9. [#17161](https://github.com/elastic/elastic-agent/pull/17161) 
* Update OTel Collector components to v0.163.0. [#17249](https://github.com/elastic/elastic-agent/pull/17249) 
* Reduce the cost of OTel status updates for receivers that run many single-stream units, like Synthetics monitors. [#17576](https://github.com/elastic/elastic-agent/pull/17576) 

### Fixes [elastic-agent-9.5.6-fixes]


* Bump npm to 12.2.1 and Node.js to 22.23.4 (24.22.1 on Wolfi) in the Elastic Agent complete Docker images to remove vulnerable `undici` copies. [#17359](https://github.com/elastic/elastic-agent/pull/17359)
* Mark the `elastic-agent-wolfi-complete` image as complete. [#16841](https://github.com/elastic/elastic-agent/pull/16841)
* Fix an OTel Collector crash when all streams for a component are disabled. [#16900](https://github.com/elastic/elastic-agent/pull/16900)
* Fix a service runtime race that left Endpoint tamper-protected after an upgrade. [#16917](https://github.com/elastic/elastic-agent/pull/16917)
* Notify Endpoint of an upgrade before the symlink swap, even when the policy arrives after the upgrade action. [#16921](https://github.com/elastic/elastic-agent/pull/16921)
* Fix Elasticsearch output parameters sending all data to the first host when running Beats as OTel receivers. [#16937](https://github.com/elastic/elastic-agent/pull/16937)
* Fix variables in Fleet policy inputs and outputs being resolved too early outside of the main Elastic Agent process. [#16972](https://github.com/elastic/elastic-agent/pull/16972)
* Rebuild the Fleet client when only the TLS or CA settings change in a policy. [#17014](https://github.com/elastic/elastic-agent/pull/17014)
* Fix Elastic Agent configured as an OTel Collector hanging on shutdown when a component fails to start. [#17027](https://github.com/elastic/elastic-agent/pull/17027)
* Fix Elastic Agent retaining component states that no broadcaster subscriber can receive. [#17107](https://github.com/elastic/elastic-agent/pull/17107)
* Fix the Ironbank Dockerfile to restore the `elastic-otel-collector` execute permission (`0755`) after a broad `chmod 0666`. [#17118](https://github.com/elastic/elastic-agent/pull/17118)
* Fix multi-valued `component.id` in Elastic Agent self-monitoring metrics. [#17233](https://github.com/elastic/elastic-agent/pull/17233) 
* Fix the artifact downloader not using the Fleet Server URI for the PGP fallback. [#17256](https://github.com/elastic/elastic-agent/pull/17256)
* Fix the OTel Collector rejecting its configuration when an input ID contains whitespace or symbols. [#17604](https://github.com/elastic/elastic-agent/pull/17604) [#17590](https://github.com/elastic/elastic-agent/issues/17590)
* Increase the kube-stack cluster collector default memory limit to `256Mi`. [#17588](https://github.com/elastic/elastic-agent/pull/17588)
* Fix an OTel Collector startup delay caused by the Elasticsearch exporter version check. [#17598](https://github.com/elastic/elastic-agent/pull/17598) [#52437](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/52437)
