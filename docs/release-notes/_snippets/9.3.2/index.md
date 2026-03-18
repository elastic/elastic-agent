## 9.3.2 [elastic-agent-release-notes-9.3.2]



### Features and enhancements [elastic-agent-9.3.2-features-enhancements]


* Allow setting component runtime per output type. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Add OpAMP extension to EDOT Collector. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Default inputs using dynamic providers to the process runtime. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Enrolling fleet-server uses internal port. [#12917](https://github.com/elastic/elastic-agent/pull/12917) 

  The bootstraping process to enroll an agent into a local fleet-server instance
  now uses the internal port (https://localhost:8221) instead of the URL flag.
  
* Rename AutoOps usage of deprecated &#34;otlphttp&#34; to &#34;otlp_http&#34;. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Update OTel Collector components to v0.145.0. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 


### Fixes [elastic-agent-9.3.2-fixes]


* Use agent log level for the otel collector even if no inputs are defined. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Prevent permission fix from failing when file is protected. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 

  The permission fix was failing when the file was protected with permissions that do not allow reading its metadata.
* Fix prometheus metrics endpoint in supervised EDOT collector. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Redact URL credentials in diagnostic outputs. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Move AutoOps sizer configuration to the batch level. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 
* Fix an issue where some components could be missing from the status output. [#13123](https://github.com/elastic/elastic-agent/pull/13123) [#13142](https://github.com/elastic/elastic-agent/pull/13142) [#13168](https://github.com/elastic/elastic-agent/pull/13168) [#13173](https://github.com/elastic/elastic-agent/pull/13173) 

  In some cases, a late update from an older component instance could overwrite a newer state.  This could cause components to be missing from the status output. With this fix, updates from older instances are ignored if a newer update has already been processed.
  

