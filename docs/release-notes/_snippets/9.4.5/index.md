## 9.4.5 [elastic-agent-release-notes-9.4.5]



### Features and enhancements [elastic-agent-9.4.5-features-enhancements]


* Add environment variables to collector diagnostics. [#15659](https://github.com/elastic/elastic-agent/pull/15659) 
* Update OTel Collector components to v0.156.0. [#15813](https://github.com/elastic/elastic-agent/pull/15813) 


### Fixes [elastic-agent-9.4.5-fixes]


* Fix orphaned `filelog` receiver in EDOT Collector helm charts. [#15731](https://github.com/elastic/elastic-agent/pull/15731) 
* Redact sensitive values in JSON diagnostic files. [#15902](https://github.com/elastic/elastic-agent/pull/15902)
* Stop upgrade rollback from being triggered by slow service component restarts. [#15863](https://github.com/elastic/elastic-agent/pull/15863)
* Fix getting current user failing on Windows when no profile directory is present. [#16006](https://github.com/elastic/elastic-agent/pull/16006) 
* Fix continuous container restarts after Fleet policy updates. [#15843](https://github.com/elastic/elastic-agent/pull/15843)
* Bake Synthetics browser binaries into the `elastic-agent-complete` image. [#16016](https://github.com/elastic/elastic-agent/pull/16016) [#15993](https://github.com/elastic/elastic-agent/issues/15993)

