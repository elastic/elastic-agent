## 9.2.4 [elastic-agent-release-notes-9.2.4]



### Features and enhancements [elastic-agent-9.2.4-features-enhancements]


* Update OTel Collector components to v0.141.0. [#12135](https://github.com/elastic/elastic-agent/pull/12135) [#12153](https://github.com/elastic/elastic-agent/pull/12153) 
* Add service.instance.id to k8s attributes in helm charts. [#12135](https://github.com/elastic/elastic-agent/pull/12135) [#12153](https://github.com/elastic/elastic-agent/pull/12153) 


### Fixes [elastic-agent-9.2.4-fixes]


* Fix signature verification using the upgrade command with the --source-uri flag for fleet-managed agents. [#12135](https://github.com/elastic/elastic-agent/pull/12135) [#12153](https://github.com/elastic/elastic-agent/pull/12153) [#11152](https://github.com/elastic/elastic-agent/issues/11152)
* Fix FLEET_TOKEN_POLICY_NAME environment variable for the container command to handle cases where there are more than 20 agent policies available. [#12135](https://github.com/elastic/elastic-agent/pull/12135) [#12153](https://github.com/elastic/elastic-agent/pull/12153) [#12069](https://github.com/elastic/elastic-agent/issues/12069)

