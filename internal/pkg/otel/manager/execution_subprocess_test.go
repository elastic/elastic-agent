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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"
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

// errCapture collects errors passed to reportErrFn under a mutex so tests can
// snapshot them safely.
type errCapture struct {
	mu   sync.Mutex
	errs []error
}

func (c *errCapture) record(_ context.Context, err error) {
	c.mu.Lock()
	c.errs = append(c.errs, err)
	c.mu.Unlock()
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

func TestProcHandle_Stopped(t *testing.T) {
	doneCh := make(chan struct{})
	h := newTestProcHandle(t, doneCh, func(context.Context, error) {})

	assert.False(t, h.Stopped())
	close(doneCh)
	assert.True(t, h.Stopped())
}

func TestProcHandle_ReportProcessExitErr(t *testing.T) {
	makeHandle := func(t *testing.T) (*procHandle, *errCapture) {
		t.Helper()
		captured := &errCapture{}
		doneCh := make(chan struct{})
		t.Cleanup(func() { close(doneCh) })
		log, err := logger.New("test", false)
		require.NoError(t, err)
		h := newProcHandle(
			&process.Info{PID: 42}, log, logp.InfoLevel,
			captured.record,
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
