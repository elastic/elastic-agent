## 9.2.4 [elastic-agent-release-notes-9.2.4]



### Features and enhancements [elastic-agent-9.2.4-features-enhancements]


* Update OTel Collector components to v0.141.0. [#11671](https://github.com/elastic/elastic-agent/pull/11671) 
* Add service.instance.id to k8s attributes in helm charts. [#11844](https://github.com/elastic/elastic-agent/pull/11844) 


### Fixes [elastic-agent-9.2.4-fixes]


* Fix signature verification using the upgrade command with the --source-uri flag for fleet-managed agents. [#11826](https://github.com/elastic/elastic-agent/pull/11826) [#11152](https://github.com/elastic/elastic-agent/issues/11152)
* Fix FLEET_TOKEN_POLICY_NAME environment variable for the container command to handle cases where there are more than 20 agent policies available. [#12073](https://github.com/elastic/elastic-agent/pull/12073) [#12069](https://github.com/elastic/elastic-agent/issues/12069)
* Handle string to []string conversion for elasticsearch config translation. [#11732](https://github.com/elastic/elastic-agent/pull/11732) [#11152](https://github.com/elastic/elastic-agent/issues/11152)