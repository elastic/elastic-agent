## 9.5.5 [elastic-agent-9.5.5-breaking-changes]


::::{dropdown} The k8s_attributes processor in Elastic Agent configured as an OTel Collector now emits stable Kubernetes semantic convention attribute names.
The OTel Collector Contrib `k8s_attributes` processor was promoted to v1.0.0 (stable) in v0.161.0.
As part of this, the `processor.k8sattributes.EmitV1K8sConventions` and
`processor.k8sattributes.DontEmitV0K8sConventions` feature gates moved from alpha to beta and are
enabled by default. The processor now emits stable semantic convention attribute names
(for example, singular `k8s.pod.label.*`, `k8s.pod.annotation.*`, `k8s.node.label.*`, `k8s.namespace.label.*`)
and no longer emits the legacy plural forms (for example, `k8s.pod.labels.*`, `k8s.pod.annotations.*`).
Refer to [Semantic Conventions Compatibility](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/k8sattributesprocessor/README.md#semantic-conventions-compatibility).


For more information, check [#16745](https://github.com/elastic/elastic-agent/pull/16745).

**Impact**<br>Dashboards, alerts, queries, ingest pipelines, or downstream processors that reference the legacy plural
attribute names (for example, `k8s.pod.labels.*`) will stop matching data produced by the `k8s_attributes` processor.


**Action**<br>Migrate to the stable attribute names, or temporarily restore the legacy names by disabling the gates.
Dual emission during a migration period is recommended:


::::
