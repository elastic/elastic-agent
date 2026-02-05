## 9.3.0 [elastic-agent-release-notes-9.3.0]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.3.0-breaking-changes) and [Known issues](/release-notes/known-issues.md)._


### Features and enhancements [elastic-agent-9.3.0-features-enhancements]


* Add support for logstash output to elastic agent standalone helm chart. [#10644](https://github.com/elastic/elastic-agent/pull/10644)
* Enable cpu and disk hostmetrics scrapers for Darwin configurations. [#11423](https://github.com/elastic/elastic-agent/pull/11423)

* Add support for downgrading a running Agent&#39;s privileges from Fleet. [#10231](https://github.com/elastic/elastic-agent/pull/10231)
* Add awss3receiver to EDOT. [#10515](https://github.com/elastic/elastic-agent/pull/10515) [#604](https://github.com/elastic/obs-integration-team/issues/604)
* Add awslogsencodingextension to EDOT. [#11107](https://github.com/elastic/elastic-agent/pull/11107)
* Add opex to elastic-agent helm chart. This change adds the Opex-CCM support to the offical elastic-agent helm chart deployment. [#9363](https://github.com/elastic/elastic-agent/pull/9363)
* Add windowseventlogreceiver to EDOT. [#11418](https://github.com/elastic/elastic-agent/pull/11418)
* Allow setting component runtime per input type. [#11186](https://github.com/elastic/elastic-agent/pull/11186)
* Improve metrics monitoring coverage for OTel-based ingestion. [#11813](https://github.com/elastic/elastic-agent/pull/11813)

  Extend ingestion of OTel collector internal telemetry to give more detailed metrics, including support for both monitoring and non-monitoring components in the same collector.
* Allow manually initiating an upgrade rollback within a configurable window. [#11955](https://github.com/elastic/elastic-agent/pull/11955) [#6881](https://github.com/elastic/elastic-agent/issues/6881)
* Add SNMP receiver to EDOT Collector. [#12239](https://github.com/elastic/elastic-agent/pull/12239)
* Restore cloud-defend to the basic and complete Docker images. [#11795](https://github.com/elastic/elastic-agent/pull/11795)
* Make otel default runtime for system\metrics input. [#11613](https://github.com/elastic/elastic-agent/pull/11613)
* Update OTel Collector components to v0.141.0. [#11671](https://github.com/elastic/elastic-agent/pull/11671)
* Change default runtime for select metricbeat inputs. [#11754](https://github.com/elastic/elastic-agent/pull/11754)

  The following metricbeat inputs will use the otel runtime by default if the elasticsearch output is used:

    - &#34;activemq/metrics&#34;
    - &#34;apache/metrics&#34;
    - &#34;beat/metrics&#34;
    - &#34;containerd/metrics&#34;
    - &#34;docker/metrics&#34;
    - &#34;elasticsearch/metrics&#34;
    - &#34;etcd/metrics&#34;
    - &#34;http/metrics&#34;
    - &#34;jolokia/metrics&#34;
    - &#34;kafka/metrics&#34;
    - &#34;kibana/metrics&#34;
    - &#34;linux/metrics&#34;
    - &#34;logstash/metrics&#34;
    - &#34;memcached/metrics&#34;
    - &#34;mongodb/metrics&#34;
    - &#34;mysql/metrics&#34;
    - &#34;nats/metrics&#34;
    - &#34;nginx/metrics&#34;
    - &#34;rabbitmq/metrics&#34;
    - &#34;sql/metrics&#34;
    - &#34;stan/metrics&#34;
    - &#34;statsd/metrics&#34;
    - &#34;system/metrics&#34;
    - &#34;vsphere/metrics&#34;

  This will result in a memory reduction since fewer agentbeat processes are started, because the otel runtime runs within the collector process.  If the policy is not compatible with the otel runtime, it will fall back to the process runtime.
* Improve input not supported error message to reference installation flavors. [#11825](https://github.com/elastic/elastic-agent/pull/11825)
* Add service.instance.id to k8s attributes in helm charts. [#11844](https://github.com/elastic/elastic-agent/pull/11844)
* Reduce installation size for all versions of the Elastic Agent. [#11821](https://github.com/elastic/elastic-agent/pull/11821)

  The Elastic Agent now ships with a single elastic-otel-collector binary that contains both the
  OTEL collector, beats receivers, and beat modules. This reduces the size of the Elastic Agent roughly
  ~200MB (amount depends on the platform). The elastic-agent.exe has also been greatly reduced from ~400M to ~75M.

* Add prometheusremotewrite receiver to EDOT. [#11937](https://github.com/elastic/elastic-agent/pull/11937)
* Replace elastic-agent/collector component name with elastic-otel-collector in self-monitoring. [#12364](https://github.com/elastic/elastic-agent/pull/12364)

  Make self-monitoring metrics consistently use the name of the new elastic-otel-collector binary executing the EDOT collector and beats receivers.

* Rotated container logs can be ingested using the helm-chart by setting `kubernetes.containers.logs.rotated_logs=true`. [#11783](https://github.com/elastic/elastic-agent/pull/11783) [#11559](https://github.com/elastic/elastic-agent/issues/11559)


### Fixes [elastic-agent-9.3.0-fixes]


* Report crashing otel process cleanly with proper status reporting. [#11448](https://github.com/elastic/elastic-agent/pull/11448)
* Fix kube-stack null template evaluation for Helm v4. [#11481](https://github.com/elastic/elastic-agent/pull/11481)

* Ensure the self-monitoring configuration accounts for the runtime components actually run in. [#11300](https://github.com/elastic/elastic-agent/pull/11300)
* Add environment.yaml file to diagnostics. [#11484](https://github.com/elastic/elastic-agent/pull/11484) [#10966](https://github.com/elastic/elastic-agent/issues/10966)
* Merge multiple agent keys when loading config. [#11619](https://github.com/elastic/elastic-agent/pull/11619) [#3717](https://github.com/elastic/elastic-agent/issues/3717)
* Hide healthcheckv2 from status output. [#11718](https://github.com/elastic/elastic-agent/pull/11718)
* Set path.home for beat receivers to components directory. [#11726](https://github.com/elastic/elastic-agent/pull/11726) [#48010](https://github.com/elastic/beats/issues/48010)
* Fix signature verification using the upgrade command with the --source-uri flag for fleet-managed agents. [#11826](https://github.com/elastic/elastic-agent/pull/11826) [#11152](https://github.com/elastic/elastic-agent/issues/11152)
* Handle curve_types to []curve_types conversion for elasticsearch config translation. [#11892](https://github.com/elastic/elastic-agent/pull/11892) [#11776](https://github.com/elastic/elastic-agent/issues/11776)
* Avoid uninstall and reinstalling service components on policy changes or reassignments. [#11740](https://github.com/elastic/elastic-agent/pull/11740)
* Fix reloading agent.logging.level for standalone Elastic Agent. [#11998](https://github.com/elastic/elastic-agent/pull/11998)
* Fix FLEET_TOKEN_POLICY_NAME environment variable for the container command to handle cases where there are more than 20 agent policies available. [#12073](https://github.com/elastic/elastic-agent/pull/12073) [#12069](https://github.com/elastic/elastic-agent/issues/12069)
* This updates the kube-stack otel gateway collector endpoint to be OTEL_K8S_POD_IP as the previous value was causing an undefined log warning. [#12205](https://github.com/elastic/elastic-agent/pull/12205)
* Emit the correct error message when the app lock cannot be acquired. [#12225](https://github.com/elastic/elastic-agent/pull/12225)
* Fix diagnostics socket path for read-only container filesystems. [#12312](https://github.com/elastic/elastic-agent/pull/12312) [#11572](https://github.com/elastic/elastic-agent/issues/11572)

