## 9.2.8 [elastic-agent-release-notes-9.2.8]



### Features and enhancements [elastic-agent-9.2.8-features-enhancements]


* Update Go to v1.25.8. [#10156](https://github.com/elastic/elastic-agent/pull/10156) 
* Update OTel Collector components to v0.147.0. [#13230](https://github.com/elastic/elastic-agent/pull/13230) 


### Fixes [elastic-agent-9.2.8-fixes]


* Fix an issue where monitoring could reingest its own error logs in a feedback loop. [#12663](https://github.com/elastic/elastic-agent/pull/12663) [#12524](https://github.com/elastic/elastic-agent/issues/12524)
* Fix container enrollment so it does not re-enroll when the Fleet URL is the same. [#13187](https://github.com/elastic/elastic-agent/pull/13187) [#13185](https://github.com/elastic/elastic-agent/issues/13185)

