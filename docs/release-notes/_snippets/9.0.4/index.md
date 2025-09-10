## 9.0.4 [elastic-agent-release-notes-9.0.4]


### Features and enhancements [elastic-agent-9.0.4-features-enhancements]

* Add file logs only managed OTLP input kube-stack configuration. [#8785](https://github.com/elastic/elastic-agent/pull/8785) 


### Fixes [elastic-agent-9.0.4-fixes]

* Remove incorrect logging that unprivileged installations are in beta. [#8715](https://github.com/elastic/elastic-agent/pull/8715) [#8689](https://github.com/elastic/elastic-agent/issues/8689)

  Unprivileged installations went GA in 8.15.0: https://www.elastic.co/docs/reference/fleet/elastic-agent-unprivileged
* Ensure standalone Elastic Agent uses log level from configuration instead of persisted state. [#8784](https://github.com/elastic/elastic-agent/pull/8784) [#8137](https://github.com/elastic/elastic-agent/issues/8137)
* Resolve deadlocks in runtime checkin communication. [#8881](https://github.com/elastic/elastic-agent/pull/8881) [#7944](https://github.com/elastic/elastic-agent/issues/7944)
* Removed init.d support from RPM packages. [#8896](https://github.com/elastic/elastic-agent/pull/8896) [#8840](https://github.com/elastic/elastic-agent/issues/8840)

