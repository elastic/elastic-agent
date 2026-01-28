## 9.3.0 [elastic-agent-release-notes-9.3.0]
_[Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.3.0-breaking-changes)._

### Features and enhancements [elastic-agent-9.3.0-features-enhancements]
* Add windowsperfcounters receiver. [#11418](https://github.com/elastic/elastic-agent/pull/11418) 
* Allow setting the otel runtime per input type. [#11186](https://github.com/elastic/elastic-agent/pull/11186) 
* Add Logstash Output to Elastic Agent Standalone. [#10644](https://github.com/elastic/elastic-agent/pull/10644) 
* Handle `PRIVILEGE_LEVEL_CHANGE` action. [#10231](https://github.com/elastic/elastic-agent/pull/10231) 
* Ingest collector internal telemetry via in-process hooks. [#11813](https://github.com/elastic/elastic-agent/pull/11813) 
* Make use `compression` and GA rotated logs. [#11783](https://github.com/elastic/elastic-agent/pull/11783) 
* Add awslogsencodingextension. [#11107](https://github.com/elastic/elastic-agent/pull/11107) 
* : Enable cpu and disk hostmetrics scrapers. [#11423](https://github.com/elastic/elastic-agent/pull/11423) 
* Feat: add SNMP receiver to EDOT Collector. [#12239](https://github.com/elastic/elastic-agent/pull/12239) 
* Add awss3receiver. [#10515](https://github.com/elastic/elastic-agent/pull/10515) 
* Bundle all beats into elastic-otel-collector (make default build) [beats submodule]. [#11821](https://github.com/elastic/elastic-agent/pull/11821) 
* Upgrade otel to 0.141.0 and 1.37.0. [#11671](https://github.com/elastic/elastic-agent/pull/11671) 
* Make otel runtime default for system/metrics. [#11613](https://github.com/elastic/elastic-agent/pull/11613) 
* Improve input not supported error to mention installation flavors. [#11825](https://github.com/elastic/elastic-agent/pull/11825) 
* Add prometheus remote write receiver. [#11937](https://github.com/elastic/elastic-agent/pull/11937) 
* Limit metricbeat receiver to list of known inputs. [#11754](https://github.com/elastic/elastic-agent/pull/11754) 
* Reintroduce cloud defend to agent container images. [#11795](https://github.com/elastic/elastic-agent/pull/11795) 
* K8s: Add `service.instance.id` to k8s attributes. [#11844](https://github.com/elastic/elastic-agent/pull/11844) 

### Fixes [elastic-agent-9.3.0-fixes]
* Set path.home for beat receivers to be components dir. [#11726](https://github.com/elastic/elastic-agent/pull/11726) 
* Fix: spec invalid rendered values "null". [#11481](https://github.com/elastic/elastic-agent/pull/11481) 
* Add environment.yml file to diagnostics. [#11484](https://github.com/elastic/elastic-agent/pull/11484) 
* Handle curve_types to []curve_types conversion in beat es config. [#11892](https://github.com/elastic/elastic-agent/pull/11892) 
* Add default option to allow merging multiple agent config keys. [#11619](https://github.com/elastic/elastic-agent/pull/11619) 
* Container entrypoint retrieves policy and enrollment token when more than 20 are present. [#12073](https://github.com/elastic/elastic-agent/pull/12073) 
* (bugfix) log level does not change when standalone agent is reloaded or when otel runtime is used. [#11998](https://github.com/elastic/elastic-agent/pull/11998) 
* Fix signature verification using the upgrade command with the --source-uri flag for fleet-managed agents. [#11826](https://github.com/elastic/elastic-agent/pull/11826) 
* Kube-stack: Update OTel collector gateway to use OTEL_K8S_POD_IP instead of MY_POD_IP. [#12205](https://github.com/elastic/elastic-agent/pull/12205) 
* Avoid uninstalling and re-installing service components on policy change. [#11740](https://github.com/elastic/elastic-agent/pull/11740) 
* Report app lock errors correctly. [#12225](https://github.com/elastic/elastic-agent/pull/12225) 
* Hide healthcheckv2 from agent status. [#11718](https://github.com/elastic/elastic-agent/pull/11718) 
* Ensure the self-monitoring configuration knows the actual component runtime. [#11300](https://github.com/elastic/elastic-agent/pull/11300) 
* Report crashing OTEL process cleanly with proper status reporting. [#11448](https://github.com/elastic/elastic-agent/pull/11448) 
* Change elasticsearch configuration DecodeHook function to handle string to []string. [#11732](https://github.com/elastic/elastic-agent/pull/11732) 

### Other changes [elastic-agent-9.3.0-other]
* Add Kafka receiver and exporter to core components. [#10988](https://github.com/elastic/elastic-agent/pull/10988) 
