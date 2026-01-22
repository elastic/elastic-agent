// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelcol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"text/template"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/featuregate"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/mock-es/pkg/api"
)

func TestMonitoringReceiver(t *testing.T) {
	cfg := `receivers:
  elasticmonitoringreceiver:
    interval: 1s
exporters:
  elasticsearch/1:
    endpoints:
      - {{.ESEndpoint}}
    max_conns_per_host: 1
    retry:
      enabled: true
      initial_interval: 1s
      max_interval: 1m0s
      max_retries: 3
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
    logs:
      receivers: [elasticmonitoringreceiver]
      exporters:
        - elasticsearch/1
`

	monitoringReceived := make(chan mapstr.M, 1)

	var eventCount int
	deterministicHandler := func(action api.Action, event []byte) int {
		var curEvent mapstr.M
		require.NoError(t, json.Unmarshal(event, &curEvent))

		// wait for second event to ensure some metrics have non-zero values
		if ok, _ := curEvent.HasKey("beat.stats"); ok && eventCount > 0 {
			monitoringReceived <- curEvent
		}

		eventCount++
		return http.StatusOK
	}

	esURL := integration.StartMockESDeterministic(t, deterministicHandler)

	configParams := struct {
		ESEndpoint string
	}{
		ESEndpoint: esURL,
	}

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(cfg)).Execute(&configBuffer, configParams),
	)

	settings := NewSettings("test", []string{"yaml:" + configBuffer.String()})

	// enable exporter metrics
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
		"beat.stats.libbeat.output.events.total":          float64(1),
		"beat.stats.libbeat.output.events.active":         float64(0),
		"beat.stats.libbeat.output.events.acked":          float64(1),
		"beat.stats.libbeat.output.events.dropped":        float64(0),
		"beat.stats.libbeat.output.events.batches":        float64(1),
		"component.id": "elasticsearch/1",
	}

	require.Empty(t, cmp.Diff(expected, ev), "metrics do not match expected values")
}
