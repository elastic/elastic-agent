## 9.5.6 [elastic-agent-release-notes-9.5.6]



### Features and enhancements [elastic-agent-9.5.6-features-enhancements]


* Add OpenShift support to the Helm chart. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  The elastic-agent Helm chart now supports OpenShift. The chart detects
  OpenShift and creates the SecurityContextConstraints and RBAC objects that the
  agent needs to run on OpenShift. The `agent.unprivileged` value can be
  configured to run the agent with least-privilege permissions.
  
* Add OpenShift support to the Kustomize manifests. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  The elastic-agent standalone Kustomize manifests now have an OpenShift overlay
  in `deploy/kubernetes/elastic-agent-kustomize/openshift/default`. The overlay
  creates the SecurityContextConstraints and RBAC objects that the agent and
  kube-state-metrics need to run on OpenShift.
  
* Update Go to 1.26.9. [#17161](https://github.com/elastic/elastic-agent/pull/17161) 
* Update OTel Collector components to v0.163.0. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Reduce the cost of OTel status updates for receivers that run many single-stream units, like Synthetics monitors. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  A status update decoded the input statuses of a receiver once per unit. When
  one receiver runs many units with one stream each, like Synthetics monitors
  with single_receiver, every status update was quadratic in the number of
  monitors: about 3.7s for 1000 monitors.
  


### Fixes [elastic-agent-9.5.6-fixes]


* Bump npm to 12.2.1 and Node.js to 22.23.4 (24.22.1 on Wolfi) in the Elastic Agent complete Docker images to remove vulnerable undici copies. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Mark the elastic-agent-wolfi-complete image as complete. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Fix OTel collector crash when all streams for a component are disabled. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Fix service runtime race that left Endpoint tamper-protected after upgrade. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Notify Endpoint of upgrade before symlink swap even when policy arrives after the upgrade action. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Fix Elasticsearch output parameters sending all data to the first host when running beats as OTel receivers. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  When an Elasticsearch output with several hosts set `parameters`, every exporter endpoint was replaced with the
  first host, so all data was sent to that host and the others were never used.
  
* Fix variables in Fleet policy inputs and outputs being resolved too early outside of the main agent process. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  When loading the full agent configuration, the Fleet policy was merged without protecting inputs and outputs
  from go-ucfg variable expansion. Variables referencing values present in the agent&#39;s own configuration
  (`agent.*`, `host.id`, `path.*`, `runtime.*`) were substituted as unquoted text before the transpiler
  evaluated them. This broke `elastic-agent uninstall`, `elastic-agent inspect`, and switching between
  privileged and unprivileged mode for policies using such variables, for example the
  `${agent.id} == &#39;&lt;id&gt;&#39;` input conditions that Synthetics private locations assign to agents.
  
* Fleet client is rebuilt when only TLS/CA settings change in a policy. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  A policy change that only added or rotated a Fleet Server CA
  (`ssl.agent_certificate_authorities`) with the Fleet hosts list unchanged was
  silently ignored for already-enrolled agents, which kept trusting only their
  original enrollment CA. If Fleet Server then rotated its serving certificate
  to the new CA, those agents went offline with an x509 &#34;certificate signed by
  unknown authority&#34; error. The Fleet client is now rebuilt whenever the
  policy&#39;s TLS certificate or CAs change, even if the Fleet hosts stay the same.
  
* Fix EDOT collector hanging on shutdown when a component fails to start. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  The elasticmonitoring receiver waited on a channel that was only closed by the goroutine launched in `Start` causing it to hang on shutdown when a component failed to start.
  
* Fix agent retaining component states that no broadcaster subscriber can receive. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 

  The coordinator&#39;s state Broadcaster kept the last published values alive in its ring buffer even when no subscriber could still receive them. These values are now cleared, which lowers live heap for agents running many units.
  
* Fix Ironbank Dockerfile to restore elastic-otel-collector execute permission (0755) after broad 0666 chmod. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Fix multi-valued `component.id` in Elastic Agent self-monitoring metrics. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Fix artifact downloader not using Fleet Server URI for PGP fallback. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Fix the otel collector rejecting its configuration when an input ID contains whitespace or symbols. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) [#17590](https://github.com/elastic/elastic-agent/issues/17590)
* Increase kube-stack cluster collector default memory limit to 256Mi. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) 
* Fix OTel collector startup delay caused by the Elasticsearch exporter version check. [#17147](https://github.com/elastic/elastic-agent/pull/17147) [#15433](https://github.com/elastic/elastic-agent/pull/15433) [#17403](https://github.com/elastic/elastic-agent/pull/17403) [#52437](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/52437)

  The Elasticsearch exporter in contrib v0.163.0 checks the Elasticsearch version at
  startup without sending credentials, and retries the 401 response until it times out
  for Beats based inputs which are configured to retry on 401 by default.
  

