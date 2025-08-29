## 9.1.0 [elastic-agent-release-notes-9.1.0]

_This release also includes: [Deprecations](/release-notes/deprecations.md#elastic-agent-9.1.0-deprecations)._

### Features and enhancements [elastic-agent-9.1.0-features-enhancements]

* Adds a new configuration setting, `agent.upgrade.rollback.window`. [#8065](https://github.com/elastic/elastic-agent/pull/8065) [#6881](https://github.com/elastic/elastic-agent/issues/6881)

  The value of the `agent.upgrade.rollback.window` setting determines the period after upgrading
  Elastic Agent when a rollback to the previous version can be triggered. This is an optional
  setting, with a default value of `168h` (7 days). The value can be any string that is parseable
  by https://pkg.go.dev/time#ParseDuration.
  
* Remove resource/k8s processor and use k8sattributes processor for service attributes. [#8599](https://github.com/elastic/elastic-agent/pull/8599) 

  This PR removes the `resource/k8s` processor in honour of the k8sattributes processor that
  provides native support for the Service attributes:
  https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.127.0/processor/k8sattributesprocessor#configuring-recommended-resource-attributes
  
  This change is aligned with the respective Semantic Conventions&#39; guidance:
  https://opentelemetry.io/docs/specs/semconv/non-normative/k8s-attributes/#service-attributes
  
* Add elastic.agent.fips to local_metadata.  [#7112](https://github.com/elastic/elastic-agent/pull/7112)

  Add elastic.agent.fips (bool) attribute to local_metadata sent with enroll and checkin requests.
  The value of this attribute indicates if the agent is a FIPS-capable distribution.
  
* Validate pbkdf2 settings when in FIPS mode. [#7187](https://github.com/elastic/elastic-agent/pull/7187) 
* FIPS-capable agent file vault. [#7360](https://github.com/elastic/elastic-agent/pull/7360) 

  Change elastic file vault implementation to allow variable length salt sizes
  only in FIPS enabled agents.  Increase default salt size to 16 for FIPS
  compliance. Non-FIPS agents are unchanged.
  
* With this change FIPS-capable agents will only be able to upgrade to other FIPS-capable agents. This change also restricts non-fips to fips upgrades as well. [#7312](https://github.com/elastic/elastic-agent/pull/7312) [#4811](https://github.com/elastic/ingest-dev/issues/4811)
* Updated the error messages returned for fips upgrades. [#7453](https://github.com/elastic/elastic-agent/pull/7453) 
* Retry enrollment requests on any error. [#8056](https://github.com/elastic/elastic-agent/pull/8056) 

  If any error is encountered during an attempted enrollment, the elastic-agent
  will backoff and retry. Add a new --enroll-timeout flag and
  FLEET_ENROLL_TIMEOUT env var to set how long it tries for, default 10m. A
  negative value disables the timeout.
  
* Remove deprecated otel elasticsearch exporter config `*_dynamic_index` from code and samples. [#8592](https://github.com/elastic/elastic-agent/pull/8592) 
* Include the forwardconnector as an EDOT collector commponent. [#8753](https://github.com/elastic/elastic-agent/pull/8753) 

  https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector
* Update OTel components to v0.129.0.  
* Update APM Config extension to v0.4.0.  
* Update Elastic Trace processor to v0.7.0.  
* Update Elastic APM connector to v0.4.0.  
* Update API Key Auth extension to v0.2.0.  
* Update Elastic Infra Metrics processor to v0.16.0.  


### Fixes [elastic-agent-9.1.0-fixes]

* Upgrade to Go 1.24.3. [#8109](https://github.com/elastic/elastic-agent/pull/8109) 
* Correctly handle sending signal to child process. [#7738](https://github.com/elastic/elastic-agent/pull/7738) [#6875](https://github.com/elastic/elastic-agent/issues/6875)
* Preserve agent run state on DEB and RPM upgrades. [#7999](https://github.com/elastic/elastic-agent/pull/7999) [#3832](https://github.com/elastic/elastic-agent/issues/3832)
* Use --header from enrollment when communicating with Fleet Server. [#8071](https://github.com/elastic/elastic-agent/pull/8071) [#6823](https://github.com/elastic/elastic-agent/issues/6823)

  The --header option for the enrollment command now adds the headers to the communication with Fleet Server. This
  allows a proxy that requires specific headers present for traffic to flow to be placed in front of a Fleet Server
  to be used and still allowing the Elastic Agent to enroll.
  
* Address a race condition that can occur in Agent diagnostics if log rotation runs while logs are being zipped.  
* Use paths.TempDir for diagnostics actions. [#8472](https://github.com/elastic/elastic-agent/pull/8472) 
* Use Debian 11 to build linux/arm to match linux/amd64. Upgrades linux/arm64&#39;s statically linked glibc from 2.28 to 2.31. [#8497](https://github.com/elastic/elastic-agent/pull/8497) 
* Relax file ownership check to allow admin re-enrollment on Windows. [#8503](https://github.com/elastic/elastic-agent/pull/8503) [#7794](https://github.com/elastic/elastic-agent/issues/7794)

  On Windows, the agent previously enforced a strict file ownership (SID) check during re-enrollment, which prevented legitimate admin users from re-enrolling the agent if the owner did not match. This PR changes the Windows-specific logic to a no-op, allowing any admin to re-enroll the agent. This restores usability for admin users, but reintroduces the risk that privileged re-enrollment can break unprivileged installs. The Unix-specific ownership check remains unchanged.
  
* Remove incorrect logging that unprivileged installations are in beta. [#8715](https://github.com/elastic/elastic-agent/pull/8715) [#8689](https://github.com/elastic/elastic-agent/issues/8689)

  Unprivileged installations went GA in 8.15.0: https://www.elastic.co/docs/reference/fleet/elastic-agent-unprivileged
* Ensure standalone Elastic Agent uses log level from configuration instead of persisted state. [#8784](https://github.com/elastic/elastic-agent/pull/8784) [#8137](https://github.com/elastic/elastic-agent/issues/8137)
* Resolve deadlocks in runtime checkin communication. [#8881](https://github.com/elastic/elastic-agent/pull/8881) [#7944](https://github.com/elastic/elastic-agent/issues/7944)
* Removed init.d support from RPM packages. [#8896](https://github.com/elastic/elastic-agent/pull/8896) [#8840](https://github.com/elastic/elastic-agent/issues/8840)

