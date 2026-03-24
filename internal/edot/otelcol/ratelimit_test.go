// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelcol

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	mockes "github.com/elastic/mock-es/pkg/api"

	"github.com/elastic/elastic-agent/testing/integration"
)

// newLogExportRequest creates a minimal log export request with a
// single log record for use in tests.
func newLogExportRequest() plogotlp.ExportRequest {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "test-service")
	lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Body().SetStr("test log message")
	return plogotlp.NewExportRequestFromLogs(logs)
}

// startCollectorWithRatelimit creates and starts a collector with an OTLP gRPC
// receiver, the given ratelimit processor config, and an Elasticsearch exporter
// pointed at esURL. It returns the gRPC logs client and a cleanup function.
func startCollectorWithRatelimit(t *testing.T, esURL string, processorsBlock string) (plogotlp.GRPCClient, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := fmt.Sprintf(`receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "localhost:%d"
%s
exporters:
  elasticsearch:
    endpoints:
      - %s
    sending_queue:
      enabled: true
      num_consumers: 1
      queue_size: 100
      wait_for_result: true
      batch:
        flush_timeout: 100ms
        max_size: 100
        min_size: 0
        sizer: items

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [ratelimit]
      exporters: [elasticsearch]
`, port, processorsBlock, esURL)

	settings := NewSettings("test", []string{"yaml:" + cfg})
	collector, err := otelcol.NewCollector(*settings)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	wg := startCollector(ctx, t, collector, "")
	cleanup := func() {
		cancel()
		collector.Shutdown()
		wg.Wait()
	}

	require.Eventually(t, func() bool {
		return otelcol.StateRunning == collector.GetState()
	}, 10*time.Second, 200*time.Millisecond)

	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	return plogotlp.NewGRPCClient(conn), cleanup
}

// sendConcurrentLogs sends n log export requests concurrently and returns
// all gRPC errors (nil entries for successful requests).
func sendConcurrentLogs(ctx context.Context, client plogotlp.GRPCClient, n int) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := newLogExportRequest()
			_, errs[i] = client.Export(ctx, req)
		}()
	}
	wg.Wait()
	return errs
}

func TestRatelimitProcessor(t *testing.T) {
	t.Run("error_on_throttle", func(t *testing.T) {
		var eventsReceived atomic.Int32
		handler := func(_ mockes.Action, _ []byte) int {
			eventsReceived.Add(1)
			return http.StatusOK
		}
		esURL := integration.StartMockESDeterministic(t, handler)

		client, cleanup := startCollectorWithRatelimit(t, esURL, `processors:
  ratelimit:
    rate: 1
    burst: 1
    strategy: requests
    throttle_behavior: error`)
		defer cleanup()

		// Send 4 requests concurrently; with rate=1/burst=1, only 1
		// should pass and the rest should be rejected immediately.
		errs := sendConcurrentLogs(t.Context(), client, 4)

		var succeeded, rateLimited int
		for _, err := range errs {
			if err == nil {
				succeeded++
				continue
			}
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.ResourceExhausted {
				rateLimited++
				continue
			}
			t.Fatalf("unexpected error: %v", err)
		}

		assert.GreaterOrEqual(t, succeeded, 1, "expected at least one request to succeed")
		assert.GreaterOrEqual(t, rateLimited, 1, "expected at least one request to be rate limited")
		// The successful requests should have reached mock ES.
		require.Eventually(t, func() bool {
			return eventsReceived.Load() >= 1
		}, 5*time.Second, 100*time.Millisecond,
			"expected at least 1 event at mock ES")
	})

	t.Run("delay_on_throttle", func(t *testing.T) {
		arrivals := make(chan time.Time, 10)
		handler := func(_ mockes.Action, _ []byte) int {
			arrivals <- time.Now()
			return http.StatusOK
		}
		esURL := integration.StartMockESDeterministic(t, handler)

		client, cleanup := startCollectorWithRatelimit(t, esURL, `processors:
  ratelimit:
    rate: 1
    burst: 1
    strategy: records
    throttle_behavior: delay`)
		defer cleanup()

		// Send 4 requests concurrently. The processor will admit the
		// first immediately and delay the rest by ~1s each.
		const numRequests = 4
		errs := sendConcurrentLogs(t.Context(), client, numRequests)
		for i, err := range errs {
			assert.NoError(t, err, "request %d should eventually succeed", i)
		}

		// Collect arrival times at mock ES.
		var times []time.Time
		for i := 0; i < numRequests; i++ {
			select {
			case at := <-arrivals:
				times = append(times, at)
			case <-time.After(10 * time.Second):
				t.Fatalf("timed out waiting for event %d/%d", i+1, numRequests)
			}
		}

		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		spread := times[len(times)-1].Sub(times[0])
		// 4 requests at rate=1/sec with burst=1: theoretical spread ~3s.
		// Assert >= 2.5s for margin.
		assert.GreaterOrEqual(t, spread, 2500*time.Millisecond,
			"expected requests to be spread over time by the rate limiter, got %s", spread)
	})
}
