// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelcol

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/featuregate"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/elastic/beats/v7/pkg/mapstr"
	"github.com/elastic/elastic-agent/internal/edot/otelcol/components"
	"github.com/elastic/mock-es/pkg/api"
)

func TestMonitoringReceiver(t *testing.T) {
	cfg := `receivers:
  elasticmonitoringreceiver:
    interval: 1s
processors:
  elasticmonitoringprocessor:
    exporter_names:
      elasticsearch/1: elasticsearch/1
connectors:
  elasticmonitoringconnector: {}
exporters:
  elasticsearch/1:
    endpoints:
      - {{.ESEndpoint}}
    max_conns_per_host: 1
    retry:
      enabled: true
      initial_interval: 1s
      max_interval: 1m0s
      max_retries: 1
    sending_queue:
      batch:
        flush_timeout: 10s
        max_size: 1600
        min_size: 0
        sizer: items
      block_on_overflow: true
      enabled: true
      num_consumers: 1
      queue_size: 3200
      wait_for_result: true

service:
  pipelines:
    metrics:
      receivers: [elasticmonitoringreceiver]
      processors: [elasticmonitoringprocessor]
      exporters: [elasticmonitoringconnector]
    logs:
      receivers: [elasticmonitoringconnector]
      exporters:
        - elasticsearch/1
`

	monitoringReceived := make(chan mapstr.M, 1)

	var eventCount int
	failedEvents := make(map[string]struct{})
	deterministicHandler := func(action api.Action, event []byte) int {
		var curEvent mapstr.M
		require.NoError(t, json.Unmarshal(event, &curEvent))

		timestamp := curEvent["@timestamp"].(string)

		// If we've already failed this event once, succeed on retry
		if _, alreadyFailed := failedEvents[timestamp]; alreadyFailed {
			// Check if this is a beat.stats event and we have enough events processed
			if _, ok := curEvent["beat.stats.libbeat.pipeline.queue.max_events"]; ok && eventCount > 3 {
				monitoringReceived <- curEvent
				return http.StatusOK
			}
			return http.StatusOK
		}

		// First time seeing this event, fail it
		failedEvents[timestamp] = struct{}{}
		eventCount++
		return http.StatusTooManyRequests
	}

	esURL := startMockESDeterministic(t, deterministicHandler)

	configParams := struct {
		ESEndpoint string
	}{
		ESEndpoint: esURL,
	}

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(cfg)).Execute(&configBuffer, configParams),
	)

	settings := NewSettings("test", []string{"yaml:" + configBuffer.String()}, WithComponents(components.Default()))

	featuregate.GlobalRegistry().Set("telemetry.newPipelineTelemetry", true)
	collector, err := otelcol.NewCollector(*settings)
	require.NoError(t, err)
	require.NotNil(t, collector)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	wg := startCollector(ctx, t, collector, "")
	defer func() {
		cancel()
		collector.Shutdown()
		wg.Wait()
	}()

	var ev mapstr.M
	select {
	case ev = <-monitoringReceived:
		require.NotNil(t, ev, "monitoring event should not be nil")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for monitoring event")
	}

	ev = ev.Flatten()
	require.NotEmpty(t, ev["@timestamp"], "expected @timestamp to be set")
	ev.Delete("@timestamp")
	require.Greater(t, ev["beat.stats.libbeat.output.write.bytes"], float64(0))
	ev.Delete("beat.stats.libbeat.output.write.bytes")

	expected := mapstr.M{
		"beat.stats.libbeat.pipeline.queue.max_events":    float64(3200),
		"beat.stats.libbeat.pipeline.queue.filled.events": float64(0),
		"beat.stats.libbeat.pipeline.queue.filled.pct":    float64(0),
		"beat.stats.libbeat.output.events.total":          float64(3),
		"beat.stats.libbeat.output.events.active":         float64(0),
		"beat.stats.libbeat.output.events.acked":          float64(3),
		"beat.stats.libbeat.output.events.dropped":        float64(0),
		"beat.stats.libbeat.output.events.batches":        float64(6),
		"beat.stats.libbeat.output.events.failed":         float64(3),
		"component.id": "elasticsearch/1",
	}

	require.Empty(t, cmp.Diff(expected, ev), "metrics do not match expected values")
}

// TestMonitoringReceiverFailoverOutput runs the internal telemetry pipeline the agent
// generates when the monitoring output has multiple hosts and loadbalance: false.
// The first host is unreachable, so events must fail over to the
// second one, and the exporters and connector must be reported as a single output.
func TestMonitoringReceiverFailoverOutput(t *testing.T) {
	cfg := `receivers:
  elasticmonitoringreceiver/_agent-component/internal-telemetry-monitoring:
    interval: 1s
processors:
  elasticmonitoringprocessor/_agent-component/internal-telemetry-monitoring:
    exporter_names:
      elasticsearch/_agent-component/monitoring/1: elasticsearch-monitoring
      elasticsearch/_agent-component/monitoring/2: elasticsearch-monitoring
      failover/_agent-component/monitoring: elasticsearch-monitoring
connectors:
  elasticmonitoringconnector/_agent-component/internal-telemetry-monitoring: {}
  failover/_agent-component/monitoring:
    priority_levels:
      - [logs/_agent-component/monitoring/1]
      - [logs/_agent-component/monitoring/2]
    retry_interval: 1m0s
    condition:
      error:
        contains: [failed to execute the request]
    sending_queue:
      batch:
        flush_timeout: 1s
        max_size: 1600
        min_size: 0
        sizer: items
      block_on_overflow: true
      enabled: true
      num_consumers: 1
      queue_size: 3200
      wait_for_result: true
exporters:
  elasticsearch/_agent-component/monitoring/1:
    endpoints:
      - {{.UnreachableEndpoint}}
    retry:
      enabled: false
    sending_queue:
      enabled: false
  elasticsearch/_agent-component/monitoring/2:
    endpoints:
      - {{.ESEndpoint}}
    retry:
      enabled: false
    sending_queue:
      enabled: false

service:
  pipelines:
    metrics/_agent-component/internal-telemetry-monitoring:
      receivers: [elasticmonitoringreceiver/_agent-component/internal-telemetry-monitoring]
      processors: [elasticmonitoringprocessor/_agent-component/internal-telemetry-monitoring]
      exporters: [elasticmonitoringconnector/_agent-component/internal-telemetry-monitoring]
    logs/_agent-component/internal-telemetry-monitoring:
      receivers: [elasticmonitoringconnector/_agent-component/internal-telemetry-monitoring]
      exporters: [failover/_agent-component/monitoring]
    logs/_agent-component/monitoring/1:
      receivers: [failover/_agent-component/monitoring]
      exporters: [elasticsearch/_agent-component/monitoring/1]
    logs/_agent-component/monitoring/2:
      receivers: [failover/_agent-component/monitoring]
      exporters: [elasticsearch/_agent-component/monitoring/2]
`

	// Nothing listens on this port, so the first priority level fails with a connection error.
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	unreachableEndpoint := "http://" + listener.Addr().String()
	require.NoError(t, listener.Close())

	monitoringReceived := make(chan mapstr.M, 1)
	var mu sync.Mutex
	componentIDs := map[string]struct{}{}
	esURL := startMockESDeterministic(t, func(action api.Action, event []byte) int {
		var curEvent mapstr.M
		require.NoError(t, json.Unmarshal(event, &curEvent))
		curEvent = curEvent.Flatten()
		compID, _ := curEvent["component.id"].(string)
		mu.Lock()
		componentIDs[compID] = struct{}{}
		mu.Unlock()
		// The first event is reported before anything has been sent, so wait for one that
		// includes the documents delivered through the second priority level.
		if acked, _ := curEvent["beat.stats.libbeat.output.events.acked"].(float64); acked > 0 {
			select {
			case monitoringReceived <- curEvent:
			default:
			}
		}
		return http.StatusOK
	})

	configParams := struct {
		ESEndpoint          string
		UnreachableEndpoint string
	}{
		ESEndpoint:          esURL,
		UnreachableEndpoint: unreachableEndpoint,
	}

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(cfg)).Execute(&configBuffer, configParams),
	)

	settings := NewSettings("test", []string{"yaml:" + configBuffer.String()}, WithComponents(components.Default()))

	featuregate.GlobalRegistry().Set("telemetry.newPipelineTelemetry", true)
	collector, err := otelcol.NewCollector(*settings)
	require.NoError(t, err)
	require.NotNil(t, collector)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	wg := startCollector(ctx, t, collector, "")
	defer func() {
		cancel()
		collector.Shutdown()
		wg.Wait()
	}()

	var ev mapstr.M
	select {
	case ev = <-monitoringReceived:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for a monitoring event delivered through the failover connector")
	}

	require.Equal(t, "elasticsearch-monitoring", ev["component.id"])
	require.Equal(t, float64(3200), ev["beat.stats.libbeat.pipeline.queue.max_events"], "queue capacity should come from the failover connector")
	require.Greater(t, ev["beat.stats.libbeat.output.events.acked"], float64(0))
	require.Greater(t, ev["beat.stats.libbeat.output.write.bytes"], float64(0))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, map[string]struct{}{"elasticsearch-monitoring": {}}, componentIDs,
		"the exporters and the failover connector should be reported as one output")
}

func TestMonitoringReceiverRequestLevelErrors(t *testing.T) {
	cfg := `receivers:
  elasticmonitoringreceiver:
    interval: 1s
processors:
  elasticmonitoringprocessor:
    exporter_names:
      elasticsearch/1: elasticsearch/1
connectors:
  elasticmonitoringconnector: {}
exporters:
  elasticsearch/1:
    endpoints:
      - {{.ESEndpoint}}
    max_conns_per_host: 1
    retry:
      enabled: true
      retry_on_status: [429]
      initial_interval: 0.1s
      max_interval: 1s
      max_retries: 5
    sending_queue:
      batch:
        flush_timeout: 10s
        max_size: 1
        min_size: 0
        sizer: items
      block_on_overflow: true
      enabled: true
      num_consumers: 1
      queue_size: 3200
      wait_for_result: true

service:
  pipelines:
    metrics:
      receivers: [elasticmonitoringreceiver]
      processors: [elasticmonitoringprocessor]
      exporters: [elasticmonitoringconnector]
    logs:
      receivers: [elasticmonitoringconnector]
      exporters:
        - elasticsearch/1
`

	monitoringReceived := make(chan mapstr.M, 1)
	var httpRequestCount int
	var ingestedDocsCount int

	// Document-level handler
	deterministicHandler := func(action api.Action, event []byte) int {
		var curEvent mapstr.M
		require.NoError(t, json.Unmarshal(event, &curEvent))

		if _, ok := curEvent["beat.stats.libbeat.pipeline.queue.max_events"]; ok {
			// Only capture after the startup event and first interval event have been processed,
			// so the captured event reflects cumulative metrics from both prior deliveries.
			if ingestedDocsCount >= 2 {
				monitoringReceived <- curEvent
			}
			ingestedDocsCount++
		}

		return http.StatusOK
	}

	uid := uuid.Must(uuid.NewV4())
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))

	baseHandler := api.NewDeterministicAPIHandler(
		uid,
		"",
		provider,
		time.Now().Add(24*time.Hour),
		0,
		0,
		deterministicHandler,
	)

	// Wrap with HTTP-level request failure logic
	httpLevelHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only fail bulk requests, so that other requests made by the exporter
		// (e.g. version detection at startup) do not consume the failure budget.
		if !strings.HasSuffix(r.URL.Path, "/_bulk") {
			baseHandler.ServeHTTP(w, r)
			return
		}
		httpRequestCount++

		// Fail the first 3 bulk requests: initial request + retries
		if httpRequestCount <= 3 {
			// force a retry
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Too Many Requests"))
			return
		}

		// succeed after initial failures
		baseHandler.ServeHTTP(w, r)
	})

	mux := http.NewServeMux()
	mux.Handle("/", httpLevelHandler)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)

	configParams := struct {
		ESEndpoint string
	}{
		ESEndpoint: s.URL,
	}

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(cfg)).Execute(&configBuffer, configParams),
	)

	settings := NewSettings("test", []string{"yaml:" + configBuffer.String()}, WithComponents(components.Default()))

	featuregate.GlobalRegistry().Set("telemetry.newPipelineTelemetry", true)
	collector, err := otelcol.NewCollector(*settings)
	require.NoError(t, err)
	require.NotNil(t, collector)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	wg := startCollector(ctx, t, collector, "")
	defer func() {
		cancel()
		collector.Shutdown()
		wg.Wait()
	}()

	var ev mapstr.M
	select {
	case ev = <-monitoringReceived:
		require.NotNil(t, ev, "monitoring event should not be nil")
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for monitoring event")
	}

	ev = ev.Flatten()
	require.NotEmpty(t, ev["@timestamp"], "expected @timestamp to be set")
	ev.Delete("@timestamp")
	require.Greater(t, ev["beat.stats.libbeat.output.write.bytes"], float64(0))
	ev.Delete("beat.stats.libbeat.output.write.bytes")

	expected := mapstr.M{
		"beat.stats.libbeat.pipeline.queue.max_events":    float64(3200),
		"beat.stats.libbeat.pipeline.queue.filled.events": float64(0),
		"beat.stats.libbeat.pipeline.queue.filled.pct":    float64(0),
		"beat.stats.libbeat.output.events.total":          float64(2), // startup monitoring event and a second after interval
		"beat.stats.libbeat.output.events.active":         float64(0),
		"beat.stats.libbeat.output.events.acked":          float64(2), // all events acked
		"beat.stats.libbeat.output.events.dropped":        float64(0),
		"beat.stats.libbeat.output.events.batches":        float64(2), // each monitoring event is sent in its own batch
		"beat.stats.libbeat.output.events.failed":         float64(3), // from the batches that failed due to HTTP-level errors
		"component.id": "elasticsearch/1",
	}

	require.Empty(t, cmp.Diff(expected, ev), "metrics do not match expected values")
}
