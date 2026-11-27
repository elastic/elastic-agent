// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/elastic/beats/v7/pkg/config"
	"github.com/elastic/beats/v7/pkg/logp/logptest"
)

// elasticsearchMaxContentLength is the default of Elasticsearch's http.max_content_length.
const elasticsearchMaxContentLength = 100 * 1024 * 1024

func TestESToOTelConfigBatchIsSizedInBytes(t *testing.T) {
	const notAppliedWarning = "does not set the size of bulk requests"

	tests := []struct {
		name        string
		cfg         map[string]any
		wantMinSize int
		wantWarning bool
	}{
		{
			name:        "no preset",
			cfg:         map[string]any{},
			wantMinSize: batchMinSizeBytes,
		},
		{
			name:        "no preset, bulk_max_size is not applied to the batch",
			cfg:         map[string]any{"bulk_max_size": 50},
			wantMinSize: batchMinSizeBytes,
			wantWarning: true,
		},
		{
			name: "custom preset, queue.mem.flush.min_events is not applied to the batch",
			cfg: map[string]any{
				"preset":                     "custom",
				"queue.mem.events":           100,
				"queue.mem.flush.min_events": 50,
			},
			wantMinSize: batchMinSizeBytes,
			wantWarning: true,
		},
		{
			name:        "balanced preset",
			cfg:         map[string]any{"preset": "balanced"},
			wantMinSize: batchMinSizeBytes,
		},
		{
			name:        "latency preset flushes smaller batches",
			cfg:         map[string]any{"preset": "latency"},
			wantMinSize: batchMinSizeBytesLatency,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, observed := logptest.NewTestingLoggerWithObserver(t, "")
			tc.cfg["hosts"] = []string{"localhost:9200"}

			got, _, _, err := ESToOTelConfig(config.MustNewConfigFrom(tc.cfg), "", logger)
			require.NoError(t, err)

			sendingQueue, ok := got["sending_queue"].(map[string]any)
			require.True(t, ok, "sending_queue must be a map")
			batch, ok := sendingQueue["batch"].(map[string]any)
			require.True(t, ok, "sending_queue::batch must be a map")
			assert.Equal(t, "bytes", batch["sizer"])
			assert.Equal(t, batchMaxSizeBytes, batch["max_size"])
			assert.Equal(t, tc.wantMinSize, batch["min_size"])

			warned := observed.FilterMessageSnippet(notAppliedWarning).Len() > 0
			assert.Equal(t, tc.wantWarning, warned, "warning about batch settings that are not applied")
		})
	}
}

// TestESExporterKeepsBulkRequestsBelowLimit runs the Elasticsearch exporter with the translated configuration
// against a server that enforces Elasticsearch's default request size limit. It sends more data in one go than
// fits in a single request, as an input with very large events does, and checks that everything is indexed.
func TestESExporterKeepsBulkRequestsBelowLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("sends more than 100 MiB through the exporter")
	}

	const (
		numEvents = 110
		eventSize = 1024 * 1024
	)

	var (
		mu             sync.Mutex
		bulkRequests   int
		maxRequestSize int64
		indexedDocs    int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "_bulk") {
			_, _ = io.WriteString(w, `{"version":{"number":"9.5.0"}}`)
			return
		}

		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer gz.Close()
			body = gz
		}
		// Every document is two lines in the bulk body: the action and the source.
		lines := &lineCounter{}
		size, err := io.Copy(lines, body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		bulkRequests++
		maxRequestSize = max(maxRequestSize, size)
		if size > elasticsearchMaxContentLength {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		indexedDocs += lines.count / 2
		_, _ = io.WriteString(w, `{"errors":false,"items":[]}`)
	}))
	t.Cleanup(srv.Close)

	exporterCfg, _, _, err := ESToOTelConfig(config.MustNewConfigFrom(map[string]any{
		"hosts":  []string{srv.URL},
		"preset": "balanced",
	}), "", logptest.NewTestingLogger(t, ""))
	require.NoError(t, err)
	// The beatsauth extension is not available on the test host and plays no part in batching.
	delete(exporterCfg, "auth")

	factory := elasticsearchexporter.NewFactory()
	cfg := factory.CreateDefaultConfig()
	require.NoError(t, confmap.NewFromStringMap(exporterCfg).Unmarshal(cfg))

	exporter, err := factory.CreateLogs(t.Context(), exportertest.NewNopSettings(factory.Type()), cfg)
	require.NoError(t, err)
	require.NoError(t, exporter.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		assert.NoError(t, exporter.Shutdown(ctx))
	})

	logs := plog.NewLogs()
	records := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	message := strings.Repeat("a", eventSize)
	for range numEvents {
		records.AppendEmpty().Body().SetStr(message)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	require.NoError(t, exporter.ConsumeLogs(ctx, logs), "no events may be dropped")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, numEvents, indexedDocs, "all events must be indexed")
	assert.Greater(t, bulkRequests, 1, "the events do not fit in one request")
	assert.LessOrEqual(t, maxRequestSize, int64(elasticsearchMaxContentLength),
		"no request may exceed the Elasticsearch request size limit")
}

// lineCounter counts the newlines written to it.
type lineCounter struct {
	count int
}

func (c *lineCounter) Write(p []byte) (int, error) {
	c.count += bytes.Count(p, []byte{'\n'})
	return len(p), nil
}
