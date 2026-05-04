## 9.4.0 [elastic-agent-release-notes-9.4.0]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.4.0-breaking-changes)._


### Features and enhancements [elastic-agent-9.4.0-features-enhancements]


* Add support for encrypted config for standalone agents. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) [#7283](https://github.com/elastic/elastic-agent/issues/7283)

  Add a new agent.features.encrypted_config.enabled config attribute
  that enables the use of encrypted config when the agent is operating
  in stand-alone mode. Agents managed through fleet will ignore this
  flag and always use encrypted config. If this flag is present, the
  agent will encrypt config, and replace the elastic-agent.yml file
  contents with only the feature flag.
  
* Add Kafka metrics receiver to EDOT Collector. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Support logstash output for otel runtime. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add cgroup runtime extension to the EDOT collector. [#12808](https://github.com/elastic/elastic-agent/pull/12808) [#1132](https://github.com/elastic/opentelemetry-dev/issues/1132)

  Add the cgroup runtime extension to the EDOT collector. This extension will automatically set the GOMAXPROCS and GOMEMLIMIT environment variables based on the cgroup limits.
  
* Add OpAMP extension to EDOT Collector. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add verifier receiver for permission verification. [#13021](https://github.com/elastic/elastic-agent/pull/13021) 
* Reload otel collector configuration without restarting it. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add haproxy, mongodb, rabbitmq, memcached, couchdb, oracledb, vcenter, zookeeper receivers to EDOT Collector. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add config option to enable checkin request compression. [#13110](https://github.com/elastic/elastic-agent/pull/13110) 
* Add OTLP JSON connector to EDOT Collector. [#13217](https://github.com/elastic/elastic-agent/pull/13217) 
* Add Windows Add/Remove Programs registry entry for Elastic Agent. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  Elastic Agent now creates a registry entry under Windows Add/Remove Programs
  (Uninstall registry key) during installation. This makes the agent visible
  in the Windows Settings &gt; Apps list and Control Panel, and the entry is
  removed on uninstall. The registry entry includes version, publisher, install
  location, and uninstall command, and is updated on upgrade.
  
  For systems originally installed via MSI, the new entry replaces the
  MSI-generated one during the first upgrade to this version.
  
  When upgrading from a version before 9.4.0 in unprivileged mode, the new
  agent may not have permission to create the registry entry because the
  required ACL was never set by the older version. Run
  `elastic-agent windows registry update` once to create the entry and set
  the correct permissions for future upgrades.
  
* Add support for Fleet URL and token from Kubernetes Secret in Helm chart. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  The Helm chart now supports `agent.fleet.urlFromSecret` and
  `agent.fleet.tokenFromSecret` fields, allowing the Fleet URL and enrollment
  token to be read from an existing Kubernetes Secret instead of being embedded
  as plain strings in the Helm values. This is useful when using secret
  management tools such as external-secrets to distribute credentials across
  clusters without storing them in values files.
  
* Inputs using kafka or logstash output are now supported in OTel runtime. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add Azure encoding extension to EDOT Collector. [#13583](https://github.com/elastic/elastic-agent/pull/13583) 
* Change control protocol time format to RFC3339Nano. [#11923](https://github.com/elastic/elastic-agent/pull/11923) 
* Update OTel Collector components to v0.144.0. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add support for elasticsearch.parameters for beatreceiver. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Update OTel Collector components to v0.145.0. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add support for agent download auth headers. [#12962](https://github.com/elastic/elastic-agent/pull/12962) 
* Run all metricbeat inputs in an otel collector. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  The following metricbeat inputs will now use the otel runtime by default, relative to 9.3:
  
    - &#34;aerospike/metrics&#34;
    - &#34;autoops_es/metrics&#34;
    - &#34;aws/metrics&#34;
    - &#34;awsfargate/metrics&#34;
    - &#34;azure/metrics&#34;
    - &#34;cloudfoundry/metrics&#34;
    - &#34;gcp/metrics&#34;
    - &#34;haproxy/metrics&#34;
    - &#34;iis/metrics&#34;
    - &#34;kubernetes/metrics&#34;
    - &#34;meraki/metrics&#34;
    - &#34;mssql/metrics&#34;
    - &#34;openai/metrics&#34;
    - &#34;oracle/metrics&#34;
    - &#34;panw/metrics&#34;
    - &#34;postgresql/metrics&#34;
    - &#34;prometheus/metrics&#34;
    - &#34;redis/metrics&#34;
    - &#34;syncgateway/metrics&#34;
    - &#34;traefik/metrics&#34;
    - &#34;uwsgi/metrics&#34;
    - &#34;windows/metrics&#34;
    - &#34;zookeeper/metrics&#34;
  
  
  This will result in a memory reduction since fewer agentbeat processes are started, because the otel runtime runs within the collector process. If the policy is not compatible with the otel runtime, it will fall back to the process runtime.
* Use NewGCMWithRandomNonce for encrypted state storage. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) [#8926](https://github.com/elastic/elastic-agent/issues/8926)
* Update OTel Collector components to v0.147.0. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Update OTel Collector components to v0.148.0. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Update OTel Collector components to v0.149.0. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add config to suppress 409 conflict errors in elasticsearch exporter. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Update OTel Collector components to v0.150.0. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Add support for partitioning kafka records in OTEL mode. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

* Disable host.ip and host.mac resource attributes in OTel kube-stack Helm configurations to reduce document size. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  Disabled host.ip and host.mac resource attributes in the resourcedetection/system
  processor for the kube-stack daemon collector. On Kubernetes hosts, these attributes
  can expose 50&#43; entries (mostly IPv6/virtual IPs from k8s networking), adding ~2KB
  to every document. This significantly impacts cost for logs and metrics where
  metadata overhead exceeds payload size.
  


### Fixes [elastic-agent-9.4.0-fixes]


* Strip Unit.Config from components diagnostic files to prevent secret leakage. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  The components-expected and components-actual diagnostic files were leaking
  secrets (API keys, tokens) because Unit.Config contains structpb.Struct fields
  whose protobuf-style YAML nesting (kind/stringvalue/structvalue) prevented the
  standard key-based redaction from finding and redacting secret values. The fix
  strips Unit.Config from the components before serializing to YAML, removing
  the source of the leak while preserving useful debugging metadata like
  component IDs, unit IDs, types and log levels.
  
* Set debugexporter verbosity to basic in gateway collector. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) [#12878](https://github.com/elastic/elastic-agent/issues/12878)
* Fix event ingestion for agentless in otel mode. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Fix rpm --prefix installation service file not found after reboot. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  When installing with `rpm --prefix`, RPM relocates all package files under the
  prefix, including the systemd service file. The postinstall script previously
  created a symlink at /lib/systemd/system/ pointing back into the prefix mount.
  If the prefix is on a separate mount (e.g. /opt), the symlink is unresolvable
  at boot before that mount is available, causing the service to not be found.
  The fix copies the service file directly to /lib/systemd/system/ so it is
  always on the root filesystem.
  
* Persist logging level after agent restart. [#13289](https://github.com/elastic/elastic-agent/pull/13289) 

  Persist logging level on policy change, so it is persisted on agent restarts,
  instead of going back to the default, info level.
* Fix agent stuck in upgrading state after manual rollback. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) [#12910](https://github.com/elastic/elastic-agent/issues/12910)
* Fix clean stopping of beats on windows. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Fix OTel runtime monitoring underreporting failed docs on retryable errors. [#13625](https://github.com/elastic/elastic-agent/pull/13625) [#12522](https://github.com/elastic/elastic-agent/issues/12522)

  The OTel runtime monitoring now correctly counts all documents from a failed bulk request towards the `beat.stats.libbeat.output.events.failed` metric. Previously, the document count from bulk requests that failed with a retryable error (such as HTTP 429) was not included in the metric.
  
* Embedded otel extensions no longer overrides ones generated by inputs. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Make enrollment retry backoff respect context cancellation. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  The enrollment retry loop&#39;s backoff wait was not context-aware, so a
  canceled context could not interrupt the current sleep. This caused
  `elastic-agent uninstall` and graceful shutdown to block for up to
  EnrollBackoffMax (10 minutes) while the agent was retrying enrollment
  against an unreachable Fleet Server. The retry loop now exits
  immediately when the caller&#39;s context is canceled.
  
* Clean up leftover artifacts when `elastic-agent install` fails. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  When `elastic-agent install` failed, some artifacts could be left on the
  system. On Windows, the agent could also still show up in &#34;Add or Remove
  Programs&#34; even though it was not installed. These leftovers are now
  removed when the install fails.
  
* Stop MIGRATE action from inheriting source cluster configuration. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

  The MIGRATE action previously merged the source cluster&#39;s fleet
  configuration (TLS CAs, proxy settings, etc.) with the migration
  action&#39;s settings. This caused agents enrolled with a custom CA to
  fail when migrating to a cluster with a different trust chain (e.g.,
  from self-managed with a custom CA to Elastic Cloud with a public CA)
  with &#34;certificate signed by unknown authority&#34;. The migrate action now
  builds enrollment options solely from what the action provides,
  falling back to system defaults (e.g., OS trust store) for any fields
  not specified.
  
* Retry delayed enrollment on invalid token instead of failing fast. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 
* Fix OTel subprocess status reporting to use last known status on force fetch. [#13534](https://github.com/elastic/elastic-agent/pull/13534) [#13916](https://github.com/elastic/elastic-agent/pull/13916) [#13973](https://github.com/elastic/elastic-agent/pull/13973) [#13699](https://github.com/elastic/elastic-agent/pull/13699) 

