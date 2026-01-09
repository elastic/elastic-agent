## 9.1.10 [elastic-agent-release-notes-9.1.10]



### Features and enhancements [elastic-agent-9.1.10-features-enhancements]


* Add debug exporter to AutoOps OTel config sample. [#10268](https://github.com/elastic/elastic-agent/pull/10268)
* Add service.instance.id to k8s attributes in helm charts. [#11844](https://github.com/elastic/elastic-agent/pull/11844)


### Fixes [elastic-agent-9.1.10-fixes]


* Fix signature verification using the upgrade command with the --source-uri flag for fleet-managed agents. [#11826](https://github.com/elastic/elastic-agent/pull/11826) [#11152](https://github.com/elastic/elastic-agent/issues/11152)
* Fix FLEET_TOKEN_POLICY_NAME environment variable for the container command to handle cases where there are more than 20 agent policies available. [#12073](https://github.com/elastic/elastic-agent/pull/12073) [#12069](https://github.com/elastic/elastic-agent/issues/12069)
* Handle string to []string conversion for elasticsearch config translation. [#11732](https://github.com/elastic/elastic-agent/pull/11732) [#11152](https://github.com/elastic/elastic-agent/issues/11152)

