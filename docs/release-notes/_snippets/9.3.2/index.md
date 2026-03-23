## 9.3.2 [elastic-agent-release-notes-9.3.2]



### Features and enhancements [elastic-agent-9.3.2-features-enhancements]


* Allow setting component runtime per output type. [#12852](https://github.com/elastic/elastic-agent/pull/12852) 
* Add OpAMP extension to EDOT Collector. [#12857](https://github.com/elastic/elastic-agent/pull/12857) 
* Default inputs using dynamic providers to the process runtime. [#12854](https://github.com/elastic/elastic-agent/pull/12854) 
* Enrolling fleet-server uses internal port. [#12917](https://github.com/elastic/elastic-agent/pull/12917) 

  The bootstraping process to enroll an agent into a local fleet-server instance
  now uses the internal port (https://localhost:8221) instead of the URL flag.
  
* Rename AutoOps usage of deprecated `otlphttp` to `otlp_http`. [#13094](https://github.com/elastic/elastic-agent/pull/13094) 
* Update OTel Collector components to v0.145.0. [#13103](https://github.com/elastic/elastic-agent/pull/13103) 


### Fixes [elastic-agent-9.3.2-fixes]


* Use agent log level for the otel collector even if no inputs are defined. [#12880](https://github.com/elastic/elastic-agent/pull/12880) 
* Prevent permission fix from failing when file is protected. [#12909](https://github.com/elastic/elastic-agent/pull/12909) 

  The permission fix was failing when the file was protected with permissions that do not allow reading its metadata.
* Fix prometheus metrics endpoint in supervised EDOT collector. [#13010](https://github.com/elastic/elastic-agent/pull/13010) 
* Redact URL credentials in diagnostic outputs. [#13022](https://github.com/elastic/elastic-agent/pull/13022) 
* Move AutoOps sizer configuration to the batch level. [#13093](https://github.com/elastic/elastic-agent/pull/13093) 
* Fix an issue where some components could be missing from the status output. [#13119](https://github.com/elastic/elastic-agent/pull/13119) 

  In some cases, a late update from an older component instance could overwrite a newer state.  This could cause components to be missing from the status output. With this fix, updates from older instances are ignored if a newer update has already been processed.
  

