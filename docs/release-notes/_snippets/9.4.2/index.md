## 9.4.2 [elastic-agent-release-notes-9.4.2]



### Features and enhancements [elastic-agent-9.4.2-features-enhancements]


* Update OTel Collector components to v0.152.0. [#14323](https://github.com/elastic/elastic-agent/pull/14323) 


### Fixes [elastic-agent-9.4.2-fixes]


* Upgrade npm to v11 in non-wolfi elastic-agent-complete Docker images. [#14167](https://github.com/elastic/elastic-agent/pull/14167) 
* Report policy id and revision in checkin when acks are disabled. [#13938](https://github.com/elastic/elastic-agent/pull/13938) [#264983](https://github.com/elastic/kibana/issues/264983)

  Persist the applied POLICY_CHANGE action in the state store regardless of
  the disable_policy_change_acks flag, and read agent_policy_id and
  policy_revision_idx from the action&#39;s policy data fields (&#34;id&#34; and
  &#34;revision&#34;) that fleet-server actually emits. Without this, Fleet&#39;s view
  of the agent&#39;s policy revision never advanced when acks were disabled.
  
* Redact sensitive values in slice maps. [#14007](https://github.com/elastic/elastic-agent/pull/14007) [#415](https://github.com/elastic/elastic-agent-libs/issues/415)
* Ship config samples, OTel collector spec, and endpoint resources zip without executable bits. [#14117](https://github.com/elastic/elastic-agent/pull/14117) [#13960](https://github.com/elastic/elastic-agent/issues/13960)

  Several non-executable files were being installed with mode 0755 in
  Elastic Agent packages: the OTel sample configs under `otel_samples/`,
  the `elastic-otel-collector.spec.yml` file, and the
  `endpoint-security-resources.zip` resource bundle. These files now
  ship with mode 0644 across deb, rpm, tar.gz, and zip packages.
  
* Policy log level changes are applied after an agent restart. [#14078](https://github.com/elastic/elastic-agent/pull/14078) [#13196](https://github.com/elastic/elastic-agent/issues/13196)

  After an agent had been restarted, changing the log level in the Fleet
  policy had no effect, the agent kept reporting and using the previous log
  level. Policy log level changes now take effect on agents that have already
  been restarted.
  
* Correctly deduplicate privilege change actions on Linux. [#14114](https://github.com/elastic/elastic-agent/pull/14114) 
* Agent no longer fails to start when the upgrade marker file is corrupt. [#14194](https://github.com/elastic/elastic-agent/pull/14194) 

  If the machine lost power while the agent was in the middle of an upgrade,
  the upgrade marker file could be left in a broken state. This caused the
  agent to refuse to start on the next boot. The agent now moves the broken
  file out of the way (keeping it for support diagnostics) and starts up
  normally as if no upgrade was in progress. The upgrade marker file is also
  now written more safely, making this situation less likely to occur.
  
* Fix silent early-return when removing stale enrollment and upgrade artifacts. [#14234](https://github.com/elastic/elastic-agent/pull/14234) 
* Fix dangling symlink when rotating to a non-existent target. [#14238](https://github.com/elastic/elastic-agent/pull/14238) 
* Prevent upgrade watcher panic when grace period expires. [#14253](https://github.com/elastic/elastic-agent/pull/14253) 
* Notify endpoint-security just before symlink swap, not before upgrade attempt. [#14397](https://github.com/elastic/elastic-agent/pull/14397) 
* Honour --path.logs when running elastic-agent run. [#14410](https://github.com/elastic/elastic-agent/pull/14410) [#13320](https://github.com/elastic/elastic-agent/issues/13320)

  When --path.logs is explicitly set on the CLI, the agent now writes logs to the specified path even if the configuration file has agent.logging.to_stderr: true (the shipped default).
  

