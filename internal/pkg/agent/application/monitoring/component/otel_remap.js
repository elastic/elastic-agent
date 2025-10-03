// A script for use in the Beats script processor, to remap raw OTel telemetry
// from its prometheus endpoint to backwards-compatible Beats metrics fields
// that can be viewed in Agent dashboards.

function process(event) {
  // This hard-coded exporter name will not work for the general
  // (non-monitoring) use case.
  var elastic_exporter = event.Get("prometheus.labels.exporter") == "elasticsearch/_agent-component/monitoring";
  var elastic_scope = event.Get("prometheus.labels.otel_scope_name") == "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter";

  // We accept general collector fields that are scoped to the elasticsearch
  // exporter (queue metrics, sent / error stats), or fields specifically
  // scoped to the elasticsearch exporter (custom elastic metrics).
  if (!elastic_exporter && !elastic_scope) {
    event.Cancel();
    return;
  }

  // Hack: if the scope is elastic-custom fields, deterministically mangle the
  // agent.id. Since the label set is different, these are passed through in
  // different events, and if we don't do this one of the events will be
  // rejected as a duplicate since they have the same component id, agent id,
  // and metricset.
  var id = event.Get("agent.id");
  if (id != null && id.length > 0) {
    // Increment / wrap the last hex character of the uuid
    var prefix = id.substring(0, id.length - 1);
    var last = id.substring(id.length - 1);
    var rotated = "0";
    if (last < "f") {
      rotated = String.fromCharCode(last.charCodeAt(0) + 1);
    }
    id = prefix + rotated;
    event.Put("agent.id", id);
  }

  // The event will be discarded unless we find some valid metric to convert.
	var keep_event = false;

	var queue_size = event.Get("prometheus.metrics.otelcol_exporter_queue_size");
	var queue_capacity = event.Get("prometheus.metrics.otelcol_exporter_queue_capacity");
  if (queue_size != null) {
  	keep_event = true;
    event.Put("beat.stats.libbeat.pipeline.queue.filled.events", queue_size);
  }
  if (queue_capacity != null) {
  	keep_event = true;
    event.Put("beat.stats.libbeat.pipeline.queue.max_events", queue_capacity);
  }
	if (queue_size != null && queue_capacity != null) {
		var queue_pct = queue_size / queue_capacity;
		if (!isNaN(queue_pct)) {
			event.Put("beat.stats.libbeat.pipeline.queue.filled.pct", queue_pct);
		}
	}
  
  var total_sent = 0;
  var total_sent_valid = false;
  // Add send statistics from all source types
  var sent_logs = event.Get("prometheus.metrics.otelcol_exporter_sent_log_records_total");
  if (sent_logs != null) {
    total_sent += sent_logs;
    total_sent_valid = true;
  }
  var sent_spans = event.Get("prometheus.metrics.otelcol_exporter_sent_spans_total");
  if (sent_spans != null) {
    total_sent += sent_spans;
    total_sent_valid = true;
  }
  var sent_metrics = event.Get("prometheus.metrics.otelcol_exporter_sent_metric_points_total");
  if (sent_metrics != null) {
    total_sent += sent_metrics;
    total_sent_valid = true;
  }
  if (total_sent_valid) {
    event.Put("beat.stats.libbeat.output.events.acked", total_sent);
  	keep_event = true;
  }

  var total_failed = 0;
  var total_failed_valid = false;
  // Add failed statistics from all source types
  var failed_logs = event.Get("prometheus.metrics.otelcol_exporter_send_failed_log_records_total");
  if (failed_logs != null) {
    total_failed += failed_logs;
    total_failed_valid = true;
  }
  var failed_spans = event.Get("prometheus.metrics.otelcol_exporter_send_failed_spans_total");
  if (failed_spans != null) {
    total_failed += failed_spans;
    total_failed_valid = true;
  }
  var failed_metrics = event.Get("prometheus.metrics.otelcol_exporter_send_failed_metric_points_total");
  if (failed_metrics != null) {
    total_failed += failed_metrics;
    total_failed_valid = true;
  }
  if (total_failed_valid) {
    event.Put("beat.stats.libbeat.output.events.dropped", total_failed);
  	keep_event = true;
  }

  var flushed_bytes = event.Get("prometheus.metrics.otelcol_elasticsearch_flushed_bytes_total");
  if (flushed_bytes != null) {
    event.Put("beat.stats.libbeat.output.write.bytes", flushed_bytes);
  	keep_event = true;
  }

  var retried_docs = event.Get("prometheus.metrics.otelcol_elasticsearch_docs_retried_ratio_total");
  if (retried_docs != null) {
    // "failed" in the beats metric means an event failed to ingest but was
    // not dropped, and will be retried.
    event.Put("beat.stats.libbeat.output.events.failed", retried_docs);
  	keep_event = true;
  }

  var request_count = event.Get("prometheus.metrics.otelcol_elasticsearch_bulk_requests_count_ratio_total");
  if (request_count != null) {
    // This is not an exact semantic match for how Beats measures batch count,
    // but it's close.
    event.Put("beat.stats.libbeat.output.events.batches", request_count);
  	keep_event = true;
  }

  var processed_docs_count = event.Get("prometheus.metrics.otelcol_elasticsearch_docs_processed_ratio_total");
  if (processed_docs_count != null) {
    // Approximate semantic match: the otel metric counts all document
    // ingestion attempts, including success, failure, and retries,
    // which is a better match for the Beats definition of total events
    // than otelcol_elasticsearch_docs_received_ratio_total which
    // includes only unique events seen (regardless of retries etc).
    event.Put("beat.stats.libbeat.output.events.total", processed_docs_count);
  	keep_event = true;
  }

  if (!keep_event) {
    event.Cancel();
  }
}
