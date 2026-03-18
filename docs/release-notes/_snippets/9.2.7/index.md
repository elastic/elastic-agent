## 9.2.7 [elastic-agent-release-notes-9.2.7]



### Features and enhancements [elastic-agent-9.2.7-features-enhancements]


* Add OpAMP extension to EDOT Collector. [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13192](https://github.com/elastic/elastic-agent/pull/13192) 
* Enrolling fleet-server uses internal port. [#12917](https://github.com/elastic/elastic-agent/pull/12917) 

  The bootstraping process to enroll an agent into a local fleet-server instance
  now uses the internal port (https://localhost:8221) instead of the URL flag.
  
* Update OTel Collector components to v0.145.0. [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13192](https://github.com/elastic/elastic-agent/pull/13192) 


### Fixes [elastic-agent-9.2.7-fixes]


* Prevent permission fix from failing when file is protected. [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13192](https://github.com/elastic/elastic-agent/pull/13192) 

  The permission fix was failing when the file was protected with permissions that do not allow reading its metadata.
* Redact URL credentials in diagnostic outputs. [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13192](https://github.com/elastic/elastic-agent/pull/13192) 
* Move AutoOps sizer configuration to the batch level. [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13192](https://github.com/elastic/elastic-agent/pull/13192) 

