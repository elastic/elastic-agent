---
title: Elastic Agent release notes
description: Review the changes, fixes, and more in each version of Elastic Agent. To check for security updates, go to Security announcements for the Elastic Stack...
url: https://docs-v3-preview.elastic.dev/release-notes/
products:
  - Elastic Agent
---

# Elastic Agent release notes

Review the changes, fixes, and more in each version of Elastic Agent.
To check for security updates, go to [Security announcements for the Elastic Stack](https://discuss.elastic.co/c/announcements/security-announcements/31).
<admonition title="Related release notes">
  Elastic Agent integrates and manages Beats for data collection, and Beats changes may impact Elastic Agent functionality. To check for Elastic Agent changes in Beats, go to [Beats release notes](https://docs-v3-preview.elastic.dev/elastic/beats/tree/main/release-notes).
</admonition>


## 9.1.3


### Features and enhancements

- Adjust the timeout for Elastic Defend check command. [#9329](https://github.com/elastic/elastic-agent/pull/9329) [#9521](https://github.com/elastic/elastic-agent/pull/9521) [#9522](https://github.com/elastic/elastic-agent/pull/9522) [#9545](https://github.com/elastic/elastic-agent/pull/9545) [#9213](https://github.com/elastic/elastic-agent/pull/9213)
- Update OTel components to v0.130.0. [#9329](https://github.com/elastic/elastic-agent/pull/9329) [#9521](https://github.com/elastic/elastic-agent/pull/9521) [#9522](https://github.com/elastic/elastic-agent/pull/9522) [#9545](https://github.com/elastic/elastic-agent/pull/9545) [#9362](https://github.com/elastic/elastic-agent/pull/9362)


### Fixes

- Upgrade to Go 1.24.6. [#9287](https://github.com/elastic/elastic-agent/pull/9287)
- On Windows, retry saving the Agent information file to disk. [#9224](https://github.com/elastic/elastic-agent/pull/9224) [#5862](https://github.com/elastic/elastic-agent/issues/5862)  Saving the Agent information file involves renaming/moving a file to its final destination. However, on Windows, it is sometimes not possible to rename/move a file to its destination file because the destination file is locked by another process (e.g. antivirus software). For such situations, we now retry the save operation on Windows.
- Correct hints annotations parsing to resolve only `${kubernetes.*}` placeholders instead of resolving all `${...}` patterns. [#9307](https://github.com/elastic/elastic-agent/pull/9307)
- Treat exit code 28 from Endpoint binary as non-fatal. [#9320](https://github.com/elastic/elastic-agent/pull/9320)
- Fixed jitter backoff strategy reset. [#9342](https://github.com/elastic/elastic-agent/pull/9342) [#8864](https://github.com/elastic/elastic-agent/issues/8864)
- Fix Docker container failing to start with no matching vars: ${env.ELASTICSEARCH_API_KEY:} and similar errors by restoring support for `:` to set default values. [#9451](https://github.com/elastic/elastic-agent/pull/9451) [#9328](https://github.com/elastic/elastic-agent/issues/9328)
- Fix deb upgrade by stopping elastic-agent service before stopping endpoint. [#9462](https://github.com/elastic/elastic-agent/pull/9462)


## 9.1.2

_No new features, enhancements, or fixes._

## 9.1.1


### Features and enhancements

- Add k8s leader elector Otel extension. [#9261](https://github.com/elastic/elastic-agent/pull/9261) [#9262](https://github.com/elastic/elastic-agent/pull/9262) [#9065](https://github.com/elastic/elastic-agent/pull/9065)


### Fixes

- Dont overwrite elasticsearch output headers from enrollment --headers flag. [#9199](https://github.com/elastic/elastic-agent/pull/9199) [#9197](https://github.com/elastic/elastic-agent/issues/9197)


## 9.1.0

_This release also includes: [Deprecations](/release-notes/deprecations#elastic-agent-9.1.0-deprecations)._

### Features and enhancements

- Adds a new configuration setting, `agent.upgrade.rollback.window`. [#8065](https://github.com/elastic/elastic-agent/pull/8065) [#6881](https://github.com/elastic/elastic-agent/issues/6881)  The value of the `agent.upgrade.rollback.window` setting determines the period after upgrading
  Elastic Agent when a rollback to the previous version can be triggered. This is an optional
  setting, with a default value of `168h` (7 days). The value can be any string that is parseable
  by https://pkg.go.dev/time#ParseDuration.
- Remove resource/k8s processor and use k8sattributes processor for service attributes. [#8599](https://github.com/elastic/elastic-agent/pull/8599)  This PR removes the `resource/k8s` processor in honour of the k8sattributes processor that
  provides native support for the Service attributes:
  https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.127.0/processor/k8sattributesprocessor#configuring-recommended-resource-attributes  This change is aligned with the respective Semantic Conventions guidance:
  https://opentelemetry.io/docs/specs/semconv/non-normative/k8s-attributes/#service-attributes
- Add elastic.agent.fips to local_metadata.  [#7112](https://github.com/elastic/elastic-agent/pull/7112)  Add elastic.agent.fips (bool) attribute to local_metadata sent with enroll and checkin requests.
  The value of this attribute indicates if the agent is a FIPS-capable distribution.
- Validate pbkdf2 settings when in FIPS mode. [#7187](https://github.com/elastic/elastic-agent/pull/7187)
- FIPS-capable agent file vault. [#7360](https://github.com/elastic/elastic-agent/pull/7360)  Change elastic file vault implementation to allow variable length salt sizes
  only in FIPS enabled agents.  Increase default salt size to 16 for FIPS
  compliance. Non-FIPS agents are unchanged.
- With this change FIPS-capable agents will only be able to upgrade to other FIPS-capable agents. This change also restricts non-fips to fips upgrades as well. [#7312](https://github.com/elastic/elastic-agent/pull/7312) [#4811](https://github.com/elastic/ingest-dev/issues/4811)
- Updated the error messages returned for fips upgrades. [#7453](https://github.com/elastic/elastic-agent/pull/7453)
- Retry enrollment requests on any error. [#8056](https://github.com/elastic/elastic-agent/pull/8056)  If any error is encountered during an attempted enrollment, the elastic-agent
  will backoff and retry. Add a new --enroll-timeout flag and
  FLEET_ENROLL_TIMEOUT env var to set how long it tries for, default 10m. A
  negative value disables the timeout.
- Remove deprecated otel elasticsearch exporter config `*_dynamic_index` from code and samples. [#8592](https://github.com/elastic/elastic-agent/pull/8592)
- Include the forwardconnector as an EDOT collector commponent. [#8753](https://github.com/elastic/elastic-agent/pull/8753)  https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector
- Update OTel components to v0.129.0.
- Update APM Config extension to v0.4.0.
- Update Elastic Trace processor to v0.7.0.
- Update Elastic APM connector to v0.4.0.
- Update API Key Auth extension to v0.2.0.
- Update Elastic Infra Metrics processor to v0.16.0.


### Fixes

- Upgrade to Go 1.24.3. [#8109](https://github.com/elastic/elastic-agent/pull/8109)
- Correctly handle sending signal to child process. [#7738](https://github.com/elastic/elastic-agent/pull/7738) [#6875](https://github.com/elastic/elastic-agent/issues/6875)
- Preserve agent run state on DEB and RPM upgrades. [#7999](https://github.com/elastic/elastic-agent/pull/7999) [#3832](https://github.com/elastic/elastic-agent/issues/3832)
- Use --header from enrollment when communicating with Fleet Server. [#8071](https://github.com/elastic/elastic-agent/pull/8071) [#6823](https://github.com/elastic/elastic-agent/issues/6823)  The --header option for the enrollment command now adds the headers to the communication with Fleet Server. This
  allows a proxy that requires specific headers present for traffic to flow to be placed in front of a Fleet Server
  to be used and still allowing the Elastic Agent to enroll.
- Address a race condition that can occur in Agent diagnostics if log rotation runs while logs are being zipped.
- Use paths.TempDir for diagnostics actions. [#8472](https://github.com/elastic/elastic-agent/pull/8472)
- Use Debian 11 to build linux/arm to match linux/amd64. Upgrades linux/arm64s statically linked glibc from 2.28 to 2.31. [#8497](https://github.com/elastic/elastic-agent/pull/8497)
- Relax file ownership check to allow admin re-enrollment on Windows. [#8503](https://github.com/elastic/elastic-agent/pull/8503) [#7794](https://github.com/elastic/elastic-agent/issues/7794)  On Windows, the agent previously enforced a strict file ownership (SID) check during re-enrollment, which prevented legitimate admin users from re-enrolling the agent if the owner did not match. This PR changes the Windows-specific logic to a no-op, allowing any admin to re-enroll the agent. This restores usability for admin users, but reintroduces the risk that privileged re-enrollment can break unprivileged installs. The Unix-specific ownership check remains unchanged.
- Remove incorrect logging that unprivileged installations are in beta. [#8715](https://github.com/elastic/elastic-agent/pull/8715) [#8689](https://github.com/elastic/elastic-agent/issues/8689)  Unprivileged installations went GA in 8.15.0: https://www.elastic.co/docs/reference/fleet/elastic-agent-unprivileged
- Ensure standalone Elastic Agent uses log level from configuration instead of persisted state. [#8784](https://github.com/elastic/elastic-agent/pull/8784) [#8137](https://github.com/elastic/elastic-agent/issues/8137)
- Resolve deadlocks in runtime checkin communication. [#8881](https://github.com/elastic/elastic-agent/pull/8881) [#7944](https://github.com/elastic/elastic-agent/issues/7944)
- Removed init.d support from RPM packages. [#8896](https://github.com/elastic/elastic-agent/pull/8896) [#8840](https://github.com/elastic/elastic-agent/issues/8840)


## 9.0.6


### Features and enhancements

- Adjust the timeout for Elastic Defend check command. [#9523](https://github.com/elastic/elastic-agent/pull/9523) [#9524](https://github.com/elastic/elastic-agent/pull/9524) [#9542](https://github.com/elastic/elastic-agent/pull/9542) [#9213](https://github.com/elastic/elastic-agent/pull/9213)


### Fixes

- Upgrade to Go 1.24.6. [#9287](https://github.com/elastic/elastic-agent/pull/9287)
- On Windows, retry saving the Agent information file to disk. [#9224](https://github.com/elastic/elastic-agent/pull/9224) [#5862](https://github.com/elastic/elastic-agent/issues/5862)  Saving the Agent information file involves renaming/moving a file to its final destination. However, on Windows, it is sometimes not possible to rename/move a file to its destination file because the destination file is locked by another process (e.g. antivirus software). For such situations, we now retry the save operation on Windows.
- Correct hints annotations parsing to resolve only `${kubernetes.*}` placeholders instead of resolving all `${...}` patterns. [#9307](https://github.com/elastic/elastic-agent/pull/9307)
- Treat exit code 28 from Endpoint binary as non-fatal. [#9320](https://github.com/elastic/elastic-agent/pull/9320)
- Fixed jitter backoff strategy reset. [#9342](https://github.com/elastic/elastic-agent/pull/9342) [#8864](https://github.com/elastic/elastic-agent/issues/8864)
- Fix Docker container failing to start with no matching vars: ${env.ELASTICSEARCH_API_KEY:} and similar errors by restoring support for `:` to set default values. [#9451](https://github.com/elastic/elastic-agent/pull/9451) [#9328](https://github.com/elastic/elastic-agent/issues/9328)
- Fix deb upgrade by stopping elastic-agent service before upgrading. [#9462](https://github.com/elastic/elastic-agent/pull/9462)


## 9.0.5

_No new features, enhancements, or fixes._

## 9.0.4


### Features and enhancements

- Add file logs only managed OTLP input kube-stack configuration. [#8785](https://github.com/elastic/elastic-agent/pull/8785)


### Fixes

- Remove incorrect logging that unprivileged installations are in beta. [#8715](https://github.com/elastic/elastic-agent/pull/8715) [#8689](https://github.com/elastic/elastic-agent/issues/8689)  Unprivileged installations went GA in 8.15.0: https://www.elastic.co/docs/reference/fleet/elastic-agent-unprivileged
- Ensure standalone Elastic Agent uses log level from configuration instead of persisted state. [#8784](https://github.com/elastic/elastic-agent/pull/8784) [#8137](https://github.com/elastic/elastic-agent/issues/8137)
- Resolve deadlocks in runtime checkin communication. [#8881](https://github.com/elastic/elastic-agent/pull/8881) [#7944](https://github.com/elastic/elastic-agent/issues/7944)
- Removed init.d support from RPM packages. [#8896](https://github.com/elastic/elastic-agent/pull/8896) [#8840](https://github.com/elastic/elastic-agent/issues/8840)


## 9.0.3


### Features and enhancements

- Add cumulativetodeltaprocessor to EDOT collector. [#8352](https://github.com/elastic/elastic-agent/pull/8352) [#8573](https://github.com/elastic/elastic-agent/pull/8573) [#8575](https://github.com/elastic/elastic-agent/pull/8575) [#8616](https://github.com/elastic/elastic-agent/pull/8616) [#8372](https://github.com/elastic/elastic-agent/pull/8372)


### Fixes

- Address a race condition that can occur in Agent diagnostics if log rotation runs while logs are being zipped. [#8215](https://github.com/elastic/elastic-agent/pull/8215)
- Use paths.TempDir for diagnostics actions. [#8472](https://github.com/elastic/elastic-agent/pull/8472)
- Relax file ownership check to allow admin re-enrollment on Windows. [#8503](https://github.com/elastic/elastic-agent/pull/8503) [#7794](https://github.com/elastic/elastic-agent/issues/7794)  On Windows, the agent previously enforced a strict file ownership (SID) check during re-enrollment, which prevented legitimate admin users from re-enrolling the agent if the owner did not match. This PR changes the Windows-specific logic to a no-op, allowing any admin to re-enroll the agent. This restores usability for admin users, but reintroduces the risk that privileged re-enrollment can break unprivileged installs. The Unix-specific ownership check remains unchanged.


## 9.0.2


### Fixes

- Upgrade Go version to 1.24.3. [#8109](https://github.com/elastic/elastic-agent/pull/8109)
- Preserve agent run state on DEB and RPM upgrades. [#7999](https://github.com/elastic/elastic-agent/pull/7999) [#3832](https://github.com/elastic/elastic-agent/issues/3832)  Improves the upgrade process for Elastic Agent installed using DEB or RPM packages by copying the run directory from the previous installation into the new versions folder


## 9.0.1

_This release also includes: [Breaking changes](/release-notes/breaking-changes#elastic-agent-9.0.1-breaking-changes)._

### Features and enhancements

- Add nopexporter to EDOT Collector. [#7788](https://github.com/elastic/elastic-agent/pull/7788)
- Set collectors fullnameOverride for edot kube-stack values. [#7754](https://github.com/elastic/elastic-agent/pull/7754) [#7381](https://github.com/elastic/elastic-agent/issues/7381)
- Update OTel components to v0.121.0. [#7686](https://github.com/elastic/elastic-agent/pull/7686)


### Fixes

- Fix Managed OTLP Helm config to use current image repo. [#7882](https://github.com/elastic/elastic-agent/pull/7882)


## 9.0.0

_This release also includes: [Breaking changes](/release-notes/breaking-changes#elastic-agent-9.0.0-breaking-changes)._

### Features and enhancements

- Adds the Azure Asset Inventory definition to Cloudbeat for Elastic Agent [#5323](https://github.com/elastic/elastic-agent/pull/5323)
- Adds Kubernetes deployment of the Elastic Distribution of OTel Collector named "gateway" to the Helm kube-stack deployment for Elastic Agent [#6444](https://github.com/elastic/elastic-agent/pull/6444)
- Adds the filesource provider to composable inputs. The provider watches for changes of the files and updates the values of the variables when the content of the file changes for Elastic Agent [#6587](https://github.com/elastic/elastic-agent/pull/6587) and [#6362](https://github.com/elastic/elastic-agent/issues/6362)
- Adds the jmxreceiver to the Elastic Distribution of OTel Collector for Elastic Agent [#6601](https://github.com/elastic/elastic-agent/pull/6601)
- Adds support for context variables in outputs as well as a default provider prefix for Elastic Agent [#6602](https://github.com/elastic/elastic-agent/pull/6602) and [#6376](https://github.com/elastic/elastic-agent/issues/6376)
- Adds the Nginx receiver and Redis receiver OTel components for Elastic Agent [#6627](https://github.com/elastic/elastic-agent/pull/6627)
- Adds --id (ELASTIC_AGENT_ID environment variable for container) and --replace-token (FLEET_REPLACE_TOKEN environment variable for container) enrollment options for Elastic Agent [#6498](https://github.com/elastic/elastic-agent/pull/6498)
- Updates Go version to 1.22.10 in Elastic Agent [#6236](https://github.com/elastic/elastic-agent/pull/6236)
- Adds the Filebeat receiver into Elastic Agent [#5833](https://github.com/elastic/elastic-agent/pull/5833)
- Updates OTel components to v0.119.0 in Elastic Agent [#6713](https://github.com/elastic/elastic-agent/pull/6713)


### Fixes

- Fixes logical race conditions in the kubernetes_secrets provider in Elastic Agent [#6623](https://github.com/elastic/elastic-agent/pull/6623)
- Resolves the proxy to inject into agent component configurations using the Go http package in Elastic Agent [#6675](https://github.com/elastic/elastic-agent/pull/6675) and [#6209](https://github.com/elastic/elastic-agent/issues/6209)
