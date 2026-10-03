## 9.4.8 [elastic-agent-9.4.8-breaking-changes]


::::{dropdown} The k8s_attributes processor in the EDOT Collector now emits stable Kubernetes semantic convention attribute names.
The OTel Collector Contrib `k8s_attributes` processor was promoted to v1.0.0 (stable) in v0.161.0.
As part of this, the `processor.k8sattributes.EmitV1K8sConventions` and
`processor.k8sattributes.DontEmitV0K8sConventions` feature gates moved from alpha to beta and are
enabled by default. The processor now emits stable semantic convention attribute names
(e.g. singular `k8s.pod.label.*`, `k8s.pod.annotation.*`, `k8s.node.label.*`, `k8s.namespace.label.*`)
and no longer emits the legacy plural forms (e.g. `k8s.pod.labels.*`, `k8s.pod.annotations.*`).
See https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/k8sattributesprocessor/README.md#semantic-conventions-compatibility


For more information, check [#16745](https://github.com/elastic/elastic-agent/pull/16745).

**Impact**<br>Dashboards, alerts, queries, ingest pipelines, or downstream processors that reference the legacy plural
attribute names (e.g. `k8s.pod.labels.*`) will stop matching data produced by the `k8s_attributes` processor.


**Action**<br>Migrate to the stable attribute names, or temporarily restore the legacy names by disabling the gates.
Dual emission during a migration period is recommended:
`--feature-gates=-processor.k8sattributes.DontEmitV0K8sConventions,processor.k8sattributes.EmitV1K8sConventions`.
To emit only the legacy names, disable both gates.

::::
