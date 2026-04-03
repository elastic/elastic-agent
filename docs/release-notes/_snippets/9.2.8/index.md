## 9.2.8 [elastic-agent-release-notes-9.2.8]



### Features and enhancements [elastic-agent-9.2.8-features-enhancements]


* Update Go version to 1.25.8. [#10156](https://github.com/elastic/elastic-agent/pull/10156) 
* Update OTel Collector components to v0.147.0. [#13391](https://github.com/elastic/elastic-agent/pull/13391) [#13446](https://github.com/elastic/elastic-agent/pull/13446) [#13447](https://github.com/elastic/elastic-agent/pull/13447) 


### Fixes [elastic-agent-9.2.8-fixes]


* Fix an issue where monitoring could reingest its own error logs in a feedback loop. [#13391](https://github.com/elastic/elastic-agent/pull/13391) [#13446](https://github.com/elastic/elastic-agent/pull/13446) [#13447](https://github.com/elastic/elastic-agent/pull/13447) 
* Fix container enrollment to not re-enroll when the fleet_url is the same. [#13391](https://github.com/elastic/elastic-agent/pull/13391) [#13446](https://github.com/elastic/elastic-agent/pull/13446) [#13447](https://github.com/elastic/elastic-agent/pull/13447) 

