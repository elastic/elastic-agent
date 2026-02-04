## 9.2.5 [elastic-agent-release-notes-9.2.5]



### Features and enhancements [elastic-agent-9.2.5-features-enhancements]


* Support --prefix flag when installing from RPM. [#12263](https://github.com/elastic/elastic-agent/pull/12263)


### Fixes [elastic-agent-9.2.5-fixes]


* OSQuery - Add list capabilities to directories for interactive users. [#12189](https://github.com/elastic/elastic-agent/pull/12189) 

  Fixing file permission issues for osquery extensions on Windows.
  It approches the problem by adding List Content permission to Logged in users so Directory permissions are not altered by UAC when traversing Agent directory structure.
  After this user won&#39;t be prompted with UAC and when opening e.g log files, instead user will run into access denied in editor of choice. 
  Elevated editor must be used to open files that require elevated permissions.
  
* Update the kube-stack otel gateway collector endpoint to be OTEL_K8S_POD_IP as the previous value was causing an undefined log warning. [#12205](https://github.com/elastic/elastic-agent/pull/12205)
* Emit the correct error message when the app lock cannot be acquired. [#12225](https://github.com/elastic/elastic-agent/pull/12225) 
* Fix elasticsearch retry behavior in OTEL runtime for reliable delivery. [#12455](https://github.com/elastic/elastic-agent/pull/12455)

  Elastic Agent running on the OTEL runtime now retries the same Elasticsearch response codes as standalone Beats, including 5xx errors. Previously, only 429 responses were retried, which could result in dropped events under certain failure conditions.

