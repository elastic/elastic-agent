## 9.3.5 [elastic-agent-release-notes-9.3.5]



### Features and enhancements [elastic-agent-9.3.5-features-enhancements]


* Add Azure Monitor receiver to EDOT Collector. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Add Azure encoding extension to EDOT Collector. [#13583](https://github.com/elastic/elastic-agent/pull/13583) 
* Update go to v1.26.2. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Update OTel Collector components to v0.150.0. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Update OTel Collector components to v1.58.0/v0.152.0. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)


### Fixes [elastic-agent-9.3.5-fixes]


* Upgrade npm to v11 in non-wolfi elastic-agent-complete Docker images. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Fix rpm --prefix installation service file not found after reboot. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)

  When installing with `rpm --prefix`, RPM relocates all package files under the
  prefix, including the systemd service file. The postinstall script previously
  created a symlink at /lib/systemd/system/ pointing back into the prefix mount.
  If the prefix is on a separate mount (e.g. /opt), the symlink is unresolvable
  at boot before that mount is available, causing the service to not be found.
  The fix copies the service file directly to /lib/systemd/system/ so it is
  always on the root filesystem.
  
* Make enrollment retry backoff respect context cancellation. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)

  The enrollment retry loop&#39;s backoff wait was not context-aware, so a
  canceled context could not interrupt the current sleep. This caused
  `elastic-agent uninstall` and graceful shutdown to block for up to
  EnrollBackoffMax (10 minutes) while the agent was retrying enrollment
  against an unreachable Fleet Server. The retry loop now exits
  immediately when the caller&#39;s context is canceled.
  
* Clean up leftover artifacts when `elastic-agent install` fails. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)

  When `elastic-agent install` failed, some artifacts could be left on the
  system. These leftovers are now removed when the install fails.
  
* Stop MIGRATE action from inheriting source cluster configuration. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)

  The MIGRATE action previously merged the source cluster&#39;s fleet
  configuration (TLS CAs, proxy settings, etc.) with the migration
  action&#39;s settings. This caused agents enrolled with a custom CA to
  fail when migrating to a cluster with a different trust chain (e.g.,
  from self-managed with a custom CA to Elastic Cloud with a public CA)
  with &#34;certificate signed by unknown authority&#34;. The migrate action now
  builds enrollment options solely from what the action provides,
  falling back to system defaults (e.g., OS trust store) for any fields
  not specified.
  
* Report policy id and revision in checkin when acks are disabled. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#264983](https://github.com/elastic/kibana/issues/264983)

  Persist the applied POLICY_CHANGE action in the state store regardless of
  the disable_policy_change_acks flag, and read agent_policy_id and
  policy_revision_idx from the action&#39;s policy data fields (&#34;id&#34; and
  &#34;revision&#34;) that fleet-server actually emits. Without this, Fleet&#39;s view
  of the agent&#39;s policy revision never advanced when acks were disabled.
  
* Fix handling of console events on Windows. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#13586](https://github.com/elastic/elastic-agent/issues/13586)

  When Elastic Agent runs in a console on Windows and receives an event like CTRL&#43;C/CTRL&#43;BREAK, it now
  exits gracefully.
  
* Retry delayed enrollment on invalid token instead of failing fast. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Stop Windows service promptly while the agent is retrying enrollment. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)

  Stopping the Elastic Agent Windows service while it was retrying
  enrollment could hang for several minutes and cause MSI uninstall to
  fail. The service now stops promptly.
  
* Fix profiling agent daemonset for K8s versions v1.33&#43;. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Clamp non-positive agent.download.retry_sleep_init_duration to default 30s. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Redact sensitive values in slice maps. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#415](https://github.com/elastic/elastic-agent-libs/issues/415)
* Preserve unexpired available rollback agent versions during rollback. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Ship config samples, OTel collector spec, and endpoint resources zip without executable bits. [#14117](https://github.com/elastic/elastic-agent/pull/14117) [#13960](https://github.com/elastic/elastic-agent/issues/13960)

  Several non-executable files were being installed with mode 0755 in
  Elastic Agent packages: the OTel sample configs under `otel_samples/`,
  the `elastic-otel-collector.spec.yml` file, and the
  `endpoint-security-resources.zip` resource bundle. These files now
  ship with mode 0644 across deb, rpm, tar.gz, and zip packages.
  
* Policy log level changes are applied after an agent restart. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#13196](https://github.com/elastic/elastic-agent/issues/13196)

  After an agent had been restarted, changing the log level in the Fleet
  policy had no effect, the agent kept reporting and using the previous log
  level. Policy log level changes now take effect on agents that have already
  been restarted.
  
* Correctly deduplicate privilege change actions on Linux. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Agent no longer fails to start when the upgrade marker file is corrupt. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)

  If the machine lost power while the agent was in the middle of an upgrade,
  the upgrade marker file could be left in a broken state. This caused the
  agent to refuse to start on the next boot. The agent now moves the broken
  file out of the way (keeping it for support diagnostics) and starts up
  normally as if no upgrade was in progress. The upgrade marker file is also
  now written more safely, making this situation less likely to occur.
  
* Fix silent early-return when removing stale enrollment and upgrade artifacts. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Fix dangling symlink when rotating to a non-existent target. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Prevent upgrade watcher panic when grace period expires. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Notify endpoint-security just before symlink swap, not before upgrade attempt. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#12981](https://github.com/elastic/elastic-agent/issues/12981) [#14351](https://github.com/elastic/elastic-agent/issues/14351)
* Honour --path.logs when running elastic-agent run. [#12919](https://github.com/elastic/elastic-agent/pull/12919) [#14516](https://github.com/elastic/elastic-agent/pull/14516) [#14418](https://github.com/elastic/elastic-agent/pull/14418) [#13320](https://github.com/elastic/elastic-agent/issues/13320)

  When --path.logs is explicitly set on the CLI, the agent now writes logs to the specified path even if the configuration file has agent.logging.to_stderr: true (the shipped default).
  

