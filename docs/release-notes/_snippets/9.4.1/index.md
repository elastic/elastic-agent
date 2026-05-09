## 9.4.1 [elastic-agent-release-notes-9.4.1]



### Features and enhancements [elastic-agent-9.4.1-features-enhancements]


* Update go to v1.26.2. [#13683](https://github.com/elastic/elastic-agent/pull/13683) 


### Fixes [elastic-agent-9.4.1-fixes]


* Fix handling of console events on Windows. [#13862](https://github.com/elastic/elastic-agent/pull/13862) [#13586](https://github.com/elastic/elastic-agent/issues/13586)

  When Elastic Agent runs in a console on Windows and receives an event like CTRL&#43;C/CTRL&#43;BREAK, it now
  exits gracefully.
  
* Stop Windows service promptly while the agent is retrying enrollment. [#13878](https://github.com/elastic/elastic-agent/pull/13878) 

  Stopping the Elastic Agent Windows service while it was retrying
  enrollment could hang for several minutes and cause MSI uninstall to
  fail. The service now stops promptly.
  
* Fix profiling agent daemonset for K8s versions v1.33&#43;. [#13894](https://github.com/elastic/elastic-agent/pull/13894) 
* Clamp non-positive agent.download.retry_sleep_init_duration to default 30s. [#13974](https://github.com/elastic/elastic-agent/pull/13974) 
* Preserve unexpired available rollback agent versions during rollback. [#14024](https://github.com/elastic/elastic-agent/pull/14024) [#14021](https://github.com/elastic/elastic-agent/issues/14021)

