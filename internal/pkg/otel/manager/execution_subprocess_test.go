// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	otelstatus "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"
	internalstatus "github.com/elastic/elastic-agent/internal/pkg/otel/status"
	runtimeLogger "github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// fakeExitState implements processExitState for use in tests.
type fakeExitState struct {
	success bool
	pid     int
	str     string
}

func (f *fakeExitState) Success() bool  { return f.success }
func (f *fakeExitState) Pid() int       { return f.pid }
func (f *fakeExitState) String() string { return f.str }

// monitorCapture collects the outputs of reportStatusFn and reportErrFn closures
// without using channels, avoiding any risk of deadlock in synctest bubbles.
// The mutex guards concurrent writes from monitoring goroutines and reads from the
// test goroutine; use snapshot() to obtain a race-detector-safe copy for assertions.
type monitorCapture struct {
	mu       sync.Mutex
	statuses []*otelstatus.AggregateStatus
	errs     []error
}

// snapshot returns copies of both slices taken under the mutex, safe to read
// after synctest.Wait() without holding the lock.
func (c *monitorCapture) snapshot() ([]*otelstatus.AggregateStatus, []error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*otelstatus.AggregateStatus(nil), c.statuses...),
		append([]error(nil), c.errs...)
}

// noopZapWriter discards entries; used to terminate the writer chain in tests.
type noopZapWriter struct{}

func (noopZapWriter) Write(zapcore.Entry, []zapcore.Field) error { return nil }

func TestLastMessage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		writes []string // each element simulates one line written to the subprocess output
		want   string
	}{
		{
			name:   "single line error",
			writes: []string{"something went wrong\n"},
			want:   "something went wrong",
		},
		{
			name: "multi-line config unmarshal error",
			writes: []string{
				// Reproduced with upstream otel/opentelemetry-collector-contrib
				// when the config references unknown component types. The cobra
				// command writes the error to stderr; the error contains embedded
				// newlines because the config unmarshaller joins per-component
				// errors. logWriter splits on \n, producing multiple zapcore
				// entries — all plain text (no fields), so zapLast accumulates
				// them into a single message.
				"Error: failed to get config: cannot unmarshal the configuration: decoding failed due to the following error(s):\n" +
					"\n" +
					"'receivers' unknown type: \"doesnotexist1\" for id: \"doesnotexist1\"\n" +
					"'exporters' unknown type: \"doesnotexist3\" for id: \"doesnotexist3\"\n",
			},
			want: `Error: failed to get config: cannot unmarshal the configuration: decoding failed due to the following error(s):; ` +
				`'receivers' unknown type: "doesnotexist1" for id: "doesnotexist1"; ` +
				`'exporters' unknown type: "doesnotexist3" for id: "doesnotexist3"`,
		},
		{
			name: "normal JSON logs followed by plain-text error",
			writes: []string{
				// Collector startup JSON log — logWriter parses it as JSON and
				// calls zapLast.Write with non-nil fields, resetting the batch.
				`{"level":"info","ts":"2025-01-01T00:00:00Z","msg":"Everything is ready. Begin running and processing data."}` + "\n",
				// Then the binary writes a plain-text error to stderr — no JSON
				// parsing, so fields are nil and the line accumulates.
				"config validation failed\n",
			},
			want: "config validation failed",
		},
		{
			name:   "empty",
			writes: nil,
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zl := newZapLast(noopZapWriter{})
			w := runtimeLogger.NewLogWriterWithDefaults(zl, zapcore.InfoLevel)

			for _, data := range tc.writes {
				_, err := fmt.Fprint(w, data)
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.want, zl.LastMessage())
		})
	}
}

func newTestProcHandle(t *testing.T, doneCh chan struct{}, reportErrFn func(context.Context, error)) *procHandle {
	t.Helper()
	log, err := logger.New("test", false)
	require.NoError(t, err)
	h := newProcHandle(
		&process.Info{PID: 42}, log, logp.InfoLevel,
		"", 0, // healthCheckExtensionID, httpHealthCheckPort
		nil, // forceFetchStatusCh
		func(context.Context, *otelstatus.AggregateStatus) {}, // reportStatusFn (noop)
		reportErrFn,
		nil, nil, // stdOutLast, stdErrLast
	)
	h.processDoneCh = doneCh // override so tests can control it
	return h
}

func TestProcHandle_LogLevel(t *testing.T) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	h := newTestProcHandle(t, doneCh, func(context.Context, error) {})
	assert.Equal(t, logp.InfoLevel, h.LogLevel())
}

func TestProcHandle_UpdateConfigYamlBytes_LatestWins(t *testing.T) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	h := newTestProcHandle(t, doneCh, func(context.Context, error) {})

	// Send two configs rapidly; only the latest should remain.
	h.updateConfigYamlBytes([]byte("first"))
	h.updateConfigYamlBytes([]byte("second"))

	got := <-h.configCh
	assert.Equal(t, "second", string(got))

	// Channel should be empty now.
	select {
	case v := <-h.configCh:
		t.Fatalf("expected empty channel, got: %s", string(v))
	default:
	}
}

func TestProcHandle_WriteToPipe(t *testing.T) {
	doneCh := make(chan struct{})
	pipeReader, pipeWriter := io.Pipe()

	var reportedErr error
	h := newTestProcHandle(t, doneCh, func(_ context.Context, err error) { reportedErr = err })
	h.wg.Add(1)

	go func() {
		defer h.wg.Done()
		h.writeToPipe(t.Context(), pipeWriter)
	}()

	// Send a config and read it from the pipe.
	expected := []byte("receivers:\n  nop:\n")
	h.updateConfigYamlBytes(expected)

	decoder := gob.NewDecoder(pipeReader)
	var got []byte
	err := decoder.Decode(&got)
	require.NoError(t, err)
	assert.Equal(t, expected, got)

	// Close process done to stop the writer goroutine.
	close(doneCh)
	h.wg.Wait()

	assert.NoError(t, reportedErr)
}

func TestProcHandle_WriteToPipe_SuppressesClosedPipeError(t *testing.T) {
	doneCh := make(chan struct{})
	_, pipeWriter := io.Pipe()

	errCh := make(chan error, 1)
	h := newTestProcHandle(t, doneCh, func(_ context.Context, err error) { errCh <- err })
	h.wg.Add(1)

	// Close the write end before writing — io.ErrClosedPipe should be suppressed.
	pipeWriter.Close()
	go func() {
		defer h.wg.Done()
		h.writeToPipe(t.Context(), pipeWriter)
	}()

	h.updateConfigYamlBytes([]byte("test"))

	// Give the goroutine time to process, then verify no error was reported.
	select {
	case err := <-errCh:
		t.Fatalf("expected no error to be reported for closed pipe, got: %v", err)
	case <-time.After(200 * time.Millisecond):
		// no error reported — expected
	}

	close(doneCh)
	h.wg.Wait()
}

func TestProcHandle_UpdateConfig(t *testing.T) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	h := newTestProcHandle(t, doneCh, func(context.Context, error) {})

	cfg := confmap.NewFromStringMap(map[string]any{
		"receivers": map[string]any{"nop": nil},
	})
	err := h.UpdateConfig(cfg)
	require.NoError(t, err)

	got := <-h.configCh
	assert.Contains(t, string(got), "receivers")
}

func TestProcHandle_UpdateConfig_NilConfig(t *testing.T) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	h := newTestProcHandle(t, doneCh, func(context.Context, error) {})

	err := h.UpdateConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no configuration provided")
}

func TestPrepareAndSerializeConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		_, err := prepareAndSerializeConfig(nil)
		assert.Error(t, err)
	})

	t.Run("serializes to yaml", func(t *testing.T) {
		cfg := confmap.NewFromStringMap(map[string]any{"key": "value"})
		yamlBytes, err := prepareAndSerializeConfig(cfg)
		require.NoError(t, err)
		assert.Contains(t, string(yamlBytes), "key: value")
	})
}

func TestCloneCollectorStatus(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		assert.Nil(t, cloneCollectorStatus(nil))
	})

	t.Run("no_component_map", func(t *testing.T) {
		original := &otelstatus.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
		}
		cloned := cloneCollectorStatus(original)
		require.NotNil(t, cloned)
		assert.Equal(t, original.Event, cloned.Event)
		assert.Nil(t, cloned.ComponentStatusMap)
	})

	t.Run("deep_copy_of_component_map", func(t *testing.T) {
		child := &otelstatus.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
		}
		original := &otelstatus.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
			ComponentStatusMap: map[string]*otelstatus.AggregateStatus{
				"child": child,
			},
		}
		cloned := cloneCollectorStatus(original)
		require.NotNil(t, cloned)
		require.Contains(t, cloned.ComponentStatusMap, "child")
		// Mutating the original map must not affect the clone.
		delete(original.ComponentStatusMap, "child")
		assert.Contains(t, cloned.ComponentStatusMap, "child")
	})
}

func TestAddCollectorMetricsReader(t *testing.T) {
	t.Run("empty_config_adds_reader", func(t *testing.T) {
		conf := confmap.New()
		err := addCollectorMetricsReader(conf, 9090)
		require.NoError(t, err)

		readers := conf.Get("service::telemetry::metrics::readers")
		list, ok := readers.([]any)
		require.True(t, ok, "expected []any, got %T", readers)
		assert.Len(t, list, 1)
	})

	t.Run("appends_to_existing_readers", func(t *testing.T) {
		existing := map[string]any{"pull": map[string]any{"exporter": map[string]any{"otlp": map[string]any{}}}}
		conf := confmap.NewFromStringMap(map[string]any{
			"service": map[string]any{
				"telemetry": map[string]any{
					"metrics": map[string]any{
						"readers": []any{existing},
					},
				},
			},
		})
		err := addCollectorMetricsReader(conf, 9091)
		require.NoError(t, err)

		readers := conf.Get("service::telemetry::metrics::readers")
		list, ok := readers.([]any)
		require.True(t, ok)
		assert.Len(t, list, 2)
	})

	t.Run("non_list_value_returns_error", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"service": map[string]any{
				"telemetry": map[string]any{
					"metrics": map[string]any{
						"readers": "not-a-list",
					},
				},
			},
		})
		err := addCollectorMetricsReader(conf, 9092)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "couldn't convert")
	})
}

func TestRemoveManagedHealthCheckExtensionStatus(t *testing.T) {
	t.Run("no_extensions_key_is_noop", func(t *testing.T) {
		st := &otelstatus.AggregateStatus{
			Event:              componentstatus.NewEvent(componentstatus.StatusOK),
			ComponentStatusMap: map[string]*otelstatus.AggregateStatus{},
		}
		removeManagedHealthCheckExtensionStatus(st, "healthcheckv2/test")
		assert.Empty(t, st.ComponentStatusMap)
	})

	t.Run("removes_managed_extension", func(t *testing.T) {
		extID := "healthcheckv2/test"
		extensionsMap := &otelstatus.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
			ComponentStatusMap: map[string]*otelstatus.AggregateStatus{
				"extension:" + extID: {Event: componentstatus.NewEvent(componentstatus.StatusOK)},
				"extension:other":    {Event: componentstatus.NewEvent(componentstatus.StatusOK)},
			},
		}
		st := &otelstatus.AggregateStatus{
			Event:              componentstatus.NewEvent(componentstatus.StatusOK),
			ComponentStatusMap: map[string]*otelstatus.AggregateStatus{"extensions": extensionsMap},
		}
		removeManagedHealthCheckExtensionStatus(st, extID)
		assert.NotContains(t, extensionsMap.ComponentStatusMap, "extension:"+extID)
		assert.Contains(t, extensionsMap.ComponentStatusMap, "extension:other")
	})

	t.Run("missing_extension_id_is_noop", func(t *testing.T) {
		extensionsMap := &otelstatus.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
			ComponentStatusMap: map[string]*otelstatus.AggregateStatus{
				"extension:other": {Event: componentstatus.NewEvent(componentstatus.StatusOK)},
			},
		}
		st := &otelstatus.AggregateStatus{
			Event:              componentstatus.NewEvent(componentstatus.StatusOK),
			ComponentStatusMap: map[string]*otelstatus.AggregateStatus{"extensions": extensionsMap},
		}
		removeManagedHealthCheckExtensionStatus(st, "healthcheckv2/missing")
		assert.Contains(t, extensionsMap.ComponentStatusMap, "extension:other")
	})
}

func TestSubprocessExecution_GetCollectorHealthCheckPort(t *testing.T) {
	t.Run("fixed_port_returned_as_is", func(t *testing.T) {
		ex := &subprocessExecution{collectorHealthCheckPort: 12345}
		port, err := ex.getCollectorHealthCheckPort()
		require.NoError(t, err)
		assert.Equal(t, 12345, port)
	})

	t.Run("zero_port_returns_random_nonzero", func(t *testing.T) {
		ex := &subprocessExecution{collectorHealthCheckPort: 0}
		port, err := ex.getCollectorHealthCheckPort()
		require.NoError(t, err)
		assert.Greater(t, port, 0)
	})
}

func TestProcHandle_Stopped(t *testing.T) {
	doneCh := make(chan struct{})
	h := newTestProcHandle(t, doneCh, func(context.Context, error) {})

	assert.False(t, h.Stopped())
	close(doneCh)
	assert.True(t, h.Stopped())
}

func TestProcHandle_ReportProcessExitErr(t *testing.T) {
	makeHandle := func(t *testing.T) (*procHandle, *monitorCapture) {
		t.Helper()
		captured := &monitorCapture{}
		doneCh := make(chan struct{})
		t.Cleanup(func() { close(doneCh) })
		log, err := logger.New("test", false)
		require.NoError(t, err)
		h := newProcHandle(
			&process.Info{PID: 42}, log, logp.InfoLevel,
			"", 0,
			nil, // forceFetchStatusCh
			func(context.Context, *otelstatus.AggregateStatus) {}, // reportStatusFn (noop)
			func(_ context.Context, err error) { captured.errs = append(captured.errs, err) },
			newZapLast(noopZapWriter{}),
			newZapLast(noopZapWriter{}),
		)
		h.processDoneCh = doneCh
		return h, captured
	}

	t.Run("procErr_is_forwarded", func(t *testing.T) {
		h, captured := makeHandle(t)
		h.reportProcessExitErr(t.Context(), nil, errors.New("wait failed"))
		require.Len(t, captured.errs, 1)
		assert.Contains(t, captured.errs[0].Error(), "wait failed")
	})

	t.Run("failed_exit_uses_stderr", func(t *testing.T) {
		h, captured := makeHandle(t)
		require.NoError(t, h.stdErrLast.Write(zapcore.Entry{Message: "stderr message"}, nil))
		h.reportProcessExitErr(t.Context(), &fakeExitState{success: false, pid: 42, str: "exit status 1"}, nil)
		require.Len(t, captured.errs, 1)
		assert.Equal(t, "stderr message", captured.errs[0].Error())
	})

	t.Run("failed_exit_falls_back_to_stdout", func(t *testing.T) {
		h, captured := makeHandle(t)
		require.NoError(t, h.stdOutLast.Write(zapcore.Entry{Message: "stdout message"}, nil))
		h.reportProcessExitErr(t.Context(), &fakeExitState{success: false, pid: 42, str: "exit status 1"}, nil)
		require.Len(t, captured.errs, 1)
		assert.Equal(t, "stdout message", captured.errs[0].Error())
	})

	t.Run("failed_exit_falls_back_to_process_state_string", func(t *testing.T) {
		h, captured := makeHandle(t)
		h.reportProcessExitErr(t.Context(), &fakeExitState{success: false, pid: 42, str: "exit status 1"}, nil)
		require.Len(t, captured.errs, 1)
		assert.Contains(t, captured.errs[0].Error(), "exited with error")
	})

	t.Run("successful_exit_reports_nil", func(t *testing.T) {
		h, captured := makeHandle(t)
		h.reportProcessExitErr(t.Context(), &fakeExitState{success: true, pid: 42}, nil)
		require.Len(t, captured.errs, 1)
		assert.NoError(t, captured.errs[0])
	})

	t.Run("procErr_and_failed_exit_are_both_reported", func(t *testing.T) {
		// When Process.Wait() returns both an error and a non-successful state,
		// reportProcessExitErr must join both into a single error rather than
		// discarding one via an early return.
		h, captured := makeHandle(t)
		require.NoError(t, h.stdErrLast.Write(zapcore.Entry{Message: "collector crashed"}, nil))
		h.reportProcessExitErr(t.Context(), &fakeExitState{success: false, pid: 42, str: "exit status 1"}, errors.New("wait failed"))
		require.Len(t, captured.errs, 1)
		require.Error(t, captured.errs[0])
		assert.Contains(t, captured.errs[0].Error(), "wait failed")
		assert.Contains(t, captured.errs[0].Error(), "collector crashed")
	})
}

// newMonitorTestHandle creates a procHandle suitable for monitorHealth unit tests.
// It must be called from within a synctest bubble so that the waitCh it creates
// is bubble-associated.  Close the returned waitCh to simulate the process exiting.
// Reported statuses and errors are captured in the returned monitorCapture; because
// synctest.Wait() ensures all goroutines are durably blocked before the test reads
// the capture, no channel synchronisation is needed and there is no deadlock risk.
func newMonitorTestHandle(
	t *testing.T,
	fetchStatus func(context.Context, http.Client, int) (*otelstatus.AggregateStatus, error),
) (h *procHandle, captured *monitorCapture, waitCh chan struct{}) {
	t.Helper()
	log, err := logger.New("test", false)
	require.NoError(t, err)

	captured = &monitorCapture{}
	waitCh = make(chan struct{})

	h = newProcHandle(
		&process.Info{PID: 42}, log, logp.InfoLevel,
		"", 0,
		nil, // forceFetchStatusCh
		func(_ context.Context, st *otelstatus.AggregateStatus) {
			captured.mu.Lock()
			captured.statuses = append(captured.statuses, st)
			captured.mu.Unlock()
		},
		func(_ context.Context, err error) {
			captured.mu.Lock()
			captured.errs = append(captured.errs, err)
			captured.mu.Unlock()
		},
		newZapLast(noopZapWriter{}),
		newZapLast(noopZapWriter{}),
	)
	h.fetchStatus = fetchStatus
	h.waitProcess = func() (processExitState, error) {
		<-waitCh
		return nil, nil
	}
	return h, captured, waitCh
}

func TestProcHandle_MonitorHealth(t *testing.T) {
	// alwaysError simulates a collector that cannot be reached.
	alwaysError := func(_ context.Context, _ http.Client, _ int) (*otelstatus.AggregateStatus, error) {
		return nil, errors.New("connection refused")
	}

	t.Run("initial_starting_status_then_nil_on_clean_exit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h, captured, waitCh := newMonitorTestHandle(t, alwaysError)
			ctx, cancel := context.WithCancel(t.Context())
			h.startMonitoring(ctx, cancel)
			synctest.Wait()

			// The initial StatusStarting must arrive before the first poll.
			statuses, _ := captured.snapshot()
			require.Len(t, statuses, 1)
			require.NotNil(t, statuses[0])
			assert.Equal(t, componentstatus.StatusStarting, statuses[0].Status())

			// Simulate clean process exit; expect nil status and nil error.
			close(waitCh)
			synctest.Wait()

			statuses, errs := captured.snapshot()
			require.Len(t, statuses, 2)
			assert.Nil(t, statuses[1])
			require.Len(t, errs, 1)
			assert.NoError(t, errs[0])
		})
	})

	t.Run("reports_status_change", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			okStatus := internalstatus.AggregateStatus(componentstatus.StatusOK, nil)
			fetchOK := func(_ context.Context, _ http.Client, _ int) (*otelstatus.AggregateStatus, error) {
				return okStatus, nil
			}
			h, captured, waitCh := newMonitorTestHandle(t, fetchOK)
			ctx, cancel := context.WithCancel(t.Context())
			h.startMonitoring(ctx, cancel)
			synctest.Wait()

			// monitorHealth emits StatusStarting immediately, then the first poll
			// returns StatusOK (different), so both are recorded in the slice.
			statuses, _ := captured.snapshot()
			require.Len(t, statuses, 2)
			assert.Equal(t, componentstatus.StatusStarting, statuses[0].Status())
			require.NotNil(t, statuses[1])
			assert.Equal(t, componentstatus.StatusOK, statuses[1].Status())

			t.Cleanup(func() { close(waitCh) })
		})
	})

	t.Run("no_report_when_status_unchanged", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// Return the same pointer every call: timestamps are identical so
			// CompareStatuses returns true and no duplicate report is emitted.
			okStatus := internalstatus.AggregateStatus(componentstatus.StatusOK, nil)
			h, captured, waitCh := newMonitorTestHandle(t, func(_ context.Context, _ http.Client, _ int) (*otelstatus.AggregateStatus, error) {
				return okStatus, nil
			})
			ctx, cancel := context.WithCancel(t.Context())
			h.startMonitoring(ctx, cancel)
			synctest.Wait()

			// After the first iteration: StatusStarting + StatusOK (first poll, changed).
			statuses, _ := captured.snapshot()
			require.Len(t, statuses, 2)

			// Advance fake time past one poll interval; monitorHealth runs a second
			// iteration but must not emit because the status pointer is unchanged.
			time.Sleep(1500 * time.Millisecond)
			synctest.Wait()

			statuses, _ = captured.snapshot()
			assert.Len(t, statuses, 2) // no new status added

			t.Cleanup(func() { close(waitCh) })
		})
	})

	t.Run("force_fetch_re_emits_current_status", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			okStatus := internalstatus.AggregateStatus(componentstatus.StatusOK, nil)
			h, captured, waitCh := newMonitorTestHandle(t, func(_ context.Context, _ http.Client, _ int) (*otelstatus.AggregateStatus, error) {
				return okStatus, nil
			})
			// forceFetchStatusCh must be a bubble channel.
			h.forceFetchStatusCh = make(chan struct{}, 1)
			ctx, cancel := context.WithCancel(t.Context())
			h.startMonitoring(ctx, cancel)
			synctest.Wait()

			// After the first iteration: StatusStarting + StatusOK (first poll, changed).
			statuses, _ := captured.snapshot()
			require.Len(t, statuses, 2)

			// Trigger a force-fetch; the last-seen status must be re-emitted.
			h.forceFetchStatusCh <- struct{}{}
			synctest.Wait()

			statuses, _ = captured.snapshot()
			require.Len(t, statuses, 3)
			require.NotNil(t, statuses[2])
			assert.Equal(t, componentstatus.StatusOK, statuses[2].Status())

			t.Cleanup(func() { close(waitCh) })
		})
	})

	t.Run("force_fetch_uses_current_status_not_stale_map_value", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// Use a mutable status pointer that the fetch function returns.
			// This allows us to change what the fetch function returns mid-test.
			var mu sync.Mutex
			currentFetchStatus := internalstatus.AggregateStatus(componentstatus.StatusOK, nil)
			fetchFn := func(_ context.Context, _ http.Client, _ int) (*otelstatus.AggregateStatus, error) {
				mu.Lock()
				defer mu.Unlock()
				return currentFetchStatus, nil
			}

			h, captured, waitCh := newMonitorTestHandle(t, fetchFn)
			// forceFetchStatusCh must be a bubble channel.
			h.forceFetchStatusCh = make(chan struct{}, 1)
			ctx, cancel := context.WithCancel(t.Context())
			h.startMonitoring(ctx, cancel)
			synctest.Wait()

			// After the first iteration: StatusStarting + StatusOK (first poll, changed).
			statuses, _ := captured.snapshot()
			require.Len(t, statuses, 2)
			assert.Equal(t, componentstatus.StatusStarting, statuses[0].Status())
			assert.Equal(t, componentstatus.StatusOK, statuses[1].Status())

			// Change the status that the fetch function returns (simulating a status change).
			mu.Lock()
			currentFetchStatus = internalstatus.AggregateStatus(componentstatus.StatusRecoverableError, errors.New("test error"))
			mu.Unlock()

			// Advance time past one poll interval to allow the new status to be fetched.
			time.Sleep(1500 * time.Millisecond)
			synctest.Wait()

			// The new status should have been fetched and reported (changed from OK to RecoverableError).
			statuses, _ = captured.snapshot()
			require.Len(t, statuses, 3)
			assert.Equal(t, componentstatus.StatusRecoverableError, statuses[2].Status())

			// Now trigger a force-fetch; it must emit the current (new) status,
			// not a stale value that might have been cached elsewhere.
			h.forceFetchStatusCh <- struct{}{}
			synctest.Wait()

			statuses, _ = captured.snapshot()
			require.Len(t, statuses, 4)
			require.NotNil(t, statuses[3])
			assert.Equal(t, componentstatus.StatusRecoverableError, statuses[3].Status())
			assert.EqualError(t, statuses[3].Err(), "test error")

			t.Cleanup(func() { close(waitCh) })
		})
	})

	t.Run("max_failures_timer_reports_recoverable_error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h, captured, waitCh := newMonitorTestHandle(t, alwaysError)
			ctx, cancel := context.WithCancel(t.Context())
			h.startMonitoring(ctx, cancel)
			synctest.Wait()

			// Verify the initial StatusStarting report arrived.
			statuses, _ := captured.snapshot()
			require.Len(t, statuses, 1)

			// Advance fake time past the 130 s failure threshold.
			time.Sleep(131 * time.Second)
			synctest.Wait()

			statuses, _ = captured.snapshot()
			require.Len(t, statuses, 2)
			require.NotNil(t, statuses[1])
			assert.Equal(t, componentstatus.StatusRecoverableError, statuses[1].Status())
			assert.EqualError(t, statuses[1].Err(), "failed to connect to collector")

			t.Cleanup(func() { close(waitCh) })
		})
	})
}
