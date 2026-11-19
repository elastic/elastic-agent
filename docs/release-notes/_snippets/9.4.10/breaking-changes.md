## 9.4.10 [elastic-agent-9.4.10-breaking-changes]


::::{dropdown} The Elasticsearch exporter in the EDOT Collector no longer accepts its deprecated settings.
The OTel Collector Contrib Elasticsearch exporter removed the following deprecated settings in v0.165.0:
`mapping::mode`, `retry::max_requests`, `logs_dynamic_index`, `metrics_dynamic_index` and `traces_dynamic_index`.
These settings were already ignored or translated to their replacements.
See https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/52027


For more information, check [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099).

**Impact**<br>An EDOT Collector configuration that sets any of the removed settings on an `elasticsearch` exporter fails to load,
and the Collector does not start.


**Action**<br>Remove the settings from your configuration. Use `retry::max_retries` instead of `retry::max_requests`
(`max_retries` is `max_requests - 1`). To select a mapping mode other than `otel`, use the `X-Elastic-Mapping-Mode`
client metadata key or the `elastic.mapping.mode` scope attribute, and `mapping::allowed_modes` to restrict the
modes that can be selected.

::::

::::{dropdown} HTTP client and server settings in the EDOT Collector no longer accept the deprecated keep-alive settings.
OTel Collector v0.165.0 removed the deprecated top-level keep-alive settings from the shared HTTP
configuration used by HTTP-based receivers, exporters and extensions:
`idle_conn_timeout`, `max_idle_conns`, `max_idle_conns_per_host` and `disable_keep_alives` for HTTP clients,
and `idle_timeout` and `keep_alives_enabled` for HTTP servers.
See https://github.com/open-telemetry/opentelemetry-collector/pull/15973


For more information, check [#17154](https://github.com/elastic/elastic-agent/pull/17154) [#18099](https://github.com/elastic/elastic-agent/pull/18099).

**Impact**<br>An EDOT Collector configuration that sets any of the removed settings fails to load, and the Collector does not start.


**Action**<br>Move `idle_conn_timeout`, `max_idle_conns`, `max_idle_conns_per_host` and `idle_timeout` into the `keepalive` section
of the same HTTP settings, for example `keepalive::idle_conn_timeout`. Remove `disable_keep_alives` and `keep_alives_enabled`.

::::
