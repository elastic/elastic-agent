// A script for use in the Beats script processor, to remap raw OTel telemetry
// from its prometheus endpoint to backwards-compatible Beats metrics fields
// that can be viewed in Agent dashboards.

function process(event) {
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
  var sent_logs = event.Get("prometheus.metrics.otelcol_exporter_sent_log_records");
  if (sent_logs != null) {
    total_sent += sent_logs;
    total_sent_valid = true;
  }
  var sent_spans = event.Get("prometheus.metrics.otelcol_exporter_sent_spans");
  if (sent_spans != null) {
    total_sent += sent_spans;
    total_sent_valid = true;
  }
  var sent_metrics = event.Get("prometheus.metrics.otelcol_exporter_sent_metric_points");
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
  var failed_logs = event.Get("prometheus.metrics.otelcol_exporter_send_failed_log_records");
  if (failed_logs != null) {
    total_failed += failed_logs;
    total_failed_valid = true;
  }
  var failed_spans = event.Get("prometheus.metrics.otelcol_exporter_send_failed_spans");
  if (failed_spans != null) {
    total_failed += failed_spans;
    total_failed_valid = true;
  }
  var failed_metrics = event.Get("prometheus.metrics.otelcol_exporter_send_failed_metric_points");
  if (failed_metrics != null) {
    total_failed += failed_metrics;
    total_failed_valid = true;
  }
  if (total_failed_valid) {
    event.Put("beat.stats.libbeat.output.events.dropped", total_failed);
  	keep_event = true;
  }

  var flushed_bytes = event.Get("prometheus.metrics.otelcol.elasticsearch.flushed.bytes");
  if (flushed_bytes != null) {
    event.Put("beat.stats.libbeat.output.write.bytes", flushed_bytes);
  	keep_event = true;
  }

  var retried_docs = event.Get("prometheus.metrics.otelcol.elasticsearch.docs.retried");
  if (retried_docs != null) {
    // "failed" in the beats metric means an event failed to ingest but was
    // not dropped, and will be retried.
    event.Put("beat.stats.libbeat.output.events.failed", retried_docs);
  	keep_event = true;
  }

  var request_count = event.Get("prometheus.metrics.otelcol.elasticsearch.bulk_requests.count");
  if (request_count != null) {
    // This is not an exact semantic match for how Beats measures batch count,
    // but it's close.
    event.Put("beat.stats.libbeat.output.events.batches", request_count);
  	keep_event = true;
  }

  var processed_docs_count = event.Get("prometheus.metrics.otelcol.elasticsearch.docs.processed");
  if (processed_docs_count != null) {
    // Approximate semantic match: the otel metric counts all document
    // ingestion attempts, including success, failure, and retries.
    event.Put("beat.stats.libbeat.output.events.total", processed_docs_count);
  	keep_event = true;
  }

  var received_docs_count = event.Get("prometheus.metrics.otelcol.elasticsearch.docs.received");
  // This measures documents passed to the exporter regardless of outcome
  // (unaffected by success / failure / retries). This should give an
  // approximate equivalent to beat.stats.libbeat.output.events.active
  // when combined with the overall success/failure totals for the exporter.
  if (received_docs_count != null && total_sent_valid && total_failed_valid) {
    var active_count = received_docs_count - total_sent - total_failed;
    event.Put("beat.stats.libbeat.output.events.active", active_count);
    keep_event = true;
  }

  if (!keep_event) {
    event.Cancel();
  }
}
