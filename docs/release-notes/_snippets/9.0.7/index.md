## 9.0.7 [elastic-agent-release-notes-9.0.7]


### Features and enhancements [elastic-agent-9.0.7-features-enhancements]

* Bump kube-stack Helm Chart to 0.9.1 and enable the cluster collector. [#9535](https://github.com/elastic/elastic-agent/pull/9535)
* Enhanced loggers for easier debugging of upgrade related issues. [#9536](https://github.com/elastic/elastic-agent/issues/9536)


### Fixes [elastic-agent-9.0.7-fixes]

* Redact secrets from pre-config, computed-config, components-expected, and components-actual files in diagnostics archive. [#9560](https://github.com/elastic/elastic-agent/pull/9560)
* Retry service start command upon failure with 30-second delay. [#9313](https://github.com/elastic/elastic-agent/pull/9313)
* Fix reporting of scheduled upgrade details across restarts and cancels. [#9562](https://github.com/elastic/elastic-agent/pull/9562) [#8778](https://github.com/elastic/elastic-agent/issues/8778)
* Enable root user to re-enroll unprivileged agent for mac and linux. [#9603](https://github.com/elastic/elastic-agent/pull/9603) [#8544](https://github.com/elastic/elastic-agent/issues/8544)
* Fix missing liveness healthcheck during container enrollment. [#9612](https://github.com/elastic/elastic-agent/pull/9612) [#9611](https://github.com/elastic/elastic-agent/issues/9611)
* Enable admin user to re-enroll unprivileged agent for windows. [#9623](https://github.com/elastic/elastic-agent/pull/9623) [#8544](https://github.com/elastic/elastic-agent/issues/8544)
* Treat exit code 284 from Endpoint binary as non-fatal. [#9687](https://github.com/elastic/elastic-agent/pull/9687)
* Ensure failed upgrade actions are removed from queue and details are set. [#9634](https://github.com/elastic/elastic-agent/pull/9634) [#9629](https://github.com/elastic/elastic-agent/issues/9629)

