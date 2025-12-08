## 9.2.0 [elastic-agent-release-notes-9.2.0]

_This release also includes: [Breaking changes](/release-notes/breaking-changes.md#elastic-agent-9.2.0-breaking-changes) and[Deprecations](/release-notes/deprecations.md#elastic-agent-9.2.0-deprecations)._

### Features and enhancements [elastic-agent-9.2.0-features-enhancements]

* Add the tailsampling OpenTelemetry processor. [#9621](https://github.com/elastic/elastic-agent/pull/9621) 
* Add_k8seventsreceiver. [#9826](https://github.com/elastic/elastic-agent/pull/9826) [#9791](https://github.com/elastic/elastic-agent/issues/9791)

  Adds k8seventsreceiver otel component.
* Edot-profilingmetrics. [#9887](https://github.com/elastic/elastic-agent/pull/9887) 
* Edot-profilingreceiver. [#9888](https://github.com/elastic/elastic-agent/pull/9888) 

  Add profilingreceiver to EDOT.
* Add agent_policy_id and policy_revision_idx to checkin requests. [#9931](https://github.com/elastic/elastic-agent/pull/9931) [#6446](https://github.com/elastic/elastic-agent/issues/6446)

  Add agent_policy_id and policy_revision_idx attributes to checkin requests.
  These attributes are used to inform fleet-server of the policy id and revision that the agent is currently running.
  Add a feature flag to disable sending acks for POLICY_CHANGE actions on a future release.
  
* (kube-stack) Add k8seventsreceiver in kube-stack configurations. [#10086](https://github.com/elastic/elastic-agent/pull/10086) [#9791](https://github.com/elastic/elastic-agent/issues/9791)
* Remove resource/k8s processor and use k8sattributes processor for mOTEL service attributes. [#10108](https://github.com/elastic/elastic-agent/pull/10108) 

  This PR removes the `resource/k8s` processor in honour of the k8sattributes processor that
  provides native support for the Service attributes:
  https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.127.0/processor/k8sattributesprocessor#configuring-recommended-resource-attributes
  This change is aligned with the respective Semantic Conventions&#39; guidance:
  https://opentelemetry.io/docs/specs/semconv/non-normative/k8s-attributes/#service-attributes
  
* Add Logstash exporter to be used with Beats OTel receivers. [#10137](https://github.com/elastic/elastic-agent/pull/10137) 
* Add Windows Event Log receiver to EDOT Collector. [#10196](https://github.com/elastic/elastic-agent/pull/10196) 
* Add logs_metrics_traces.yml sample in EDOT for Windows. [#10514](https://github.com/elastic/elastic-agent/pull/10514) 
* Add Headers Setter extension to EDOT Collector. [#9903](https://github.com/elastic/elastic-agent/pull/9903) [#9889](https://github.com/elastic/elastic-agent/issues/9889)
* Include OTel Collector internal telemetry in Agent monitoring. [#9928](https://github.com/elastic/elastic-agent/pull/9928) 
* Add debug exporter to AutoOps OTel config sample. [#10268](https://github.com/elastic/elastic-agent/pull/10268) 
* Update OTel Collector components to v0.137.0. [#10391](https://github.com/elastic/elastic-agent/pull/10391) 


### Fixes [elastic-agent-9.2.0-fixes]

* Add special case handling for profiling in EDOT. [#10143](https://github.com/elastic/elastic-agent/pull/10143) 
* Inspect: Handle components with slashes in their name. [#10442](https://github.com/elastic/elastic-agent/pull/10442) 
* Improve OTel batching and queueing for AutoOps data shipping. [#10492](https://github.com/elastic/elastic-agent/pull/10492) 

