## 9.2.5 [elastic-agent-release-notes-9.2.5]



### Features and enhancements [elastic-agent-9.2.5-features-enhancements]


* Support --prefix flag when installing from RPM. [#12455](https://github.com/elastic/elastic-agent/pull/12455) [#12491](https://github.com/elastic/elastic-agent/pull/12491) [#12492](https://github.com/elastic/elastic-agent/pull/12492) [#11724](https://github.com/elastic/elastic-agent/pull/11724) [#141](https://github.com/elastic/elastic-agent/issues/141)


### Fixes [elastic-agent-9.2.5-fixes]


* Osquery-extensions-fix. [#12455](https://github.com/elastic/elastic-agent/pull/12455) [#12491](https://github.com/elastic/elastic-agent/pull/12491) [#12492](https://github.com/elastic/elastic-agent/pull/12492) [#11724](https://github.com/elastic/elastic-agent/pull/11724) 

  Fixing file permission issues for osquery extensions on Windows.
  It approches the problem by adding List Content permission to Logged in users so Directory permissions are not altered by UAC when traversing Agent directory structure.
  After this user won&#39;t be prompted with UAC and when opening e.g log files, instead user will run into access denied in editor of choice. 
  Elevated editor must be used to open files that require elevated permissions.
  
* This updates the kube-stack otel gateway collector endpoint to be OTEL_K8S_POD_IP as the previous value was causing an undefined log warning. [#12455](https://github.com/elastic/elastic-agent/pull/12455) [#12491](https://github.com/elastic/elastic-agent/pull/12491) [#12492](https://github.com/elastic/elastic-agent/pull/12492) [#11724](https://github.com/elastic/elastic-agent/pull/11724) 
* Emit the correct error message when the app lock cannot be acquired. [#12455](https://github.com/elastic/elastic-agent/pull/12455) [#12491](https://github.com/elastic/elastic-agent/pull/12491) [#12492](https://github.com/elastic/elastic-agent/pull/12492) [#11724](https://github.com/elastic/elastic-agent/pull/11724) 
* Fix elasticsearch retry behavior in OTEL runtime for reliable delivery. [#12455](https://github.com/elastic/elastic-agent/pull/12455) [#12491](https://github.com/elastic/elastic-agent/pull/12491) [#12492](https://github.com/elastic/elastic-agent/pull/12492) [#11724](https://github.com/elastic/elastic-agent/pull/11724) 

  Elastic Agent running on the OTEL runtime now retries the same Elasticsearch response codes as standalone Beats, including 5xx errors. Previously, only 429 responses were retried, which could result in dropped events under certain failure conditions.

