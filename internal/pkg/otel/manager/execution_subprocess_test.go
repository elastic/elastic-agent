// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"encoding/gob"
	"fmt"
	"io"
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

func newTestProcHandle(t *testing.T, doneCh chan struct{}, reportErrFn func(error)) *procHandle {
	t.Helper()
	log, err := logger.New("test", false)
	require.NoError(t, err)
	return newProcHandle(
		&process.Info{PID: 42},
		log,
		logp.InfoLevel,
		doneCh,
		reportErrFn,
	)
}

func TestProcHandle_LogLevel(t *testing.T) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	h := newTestProcHandle(t, doneCh, func(error) {})
	assert.Equal(t, logp.InfoLevel, h.LogLevel())
}

func TestProcHandle_UpdateConfigYamlBytes_LatestWins(t *testing.T) {
	doneCh := make(chan struct{})
	defer close(doneCh)

	h := newTestProcHandle(t, doneCh, func(error) {})

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
	h := newTestProcHandle(t, doneCh, func(err error) { reportedErr = err })
	h.wg.Add(1)

	go func() {
		defer h.wg.Done()
		h.writeToPipe(pipeWriter)
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
	h := newTestProcHandle(t, doneCh, func(err error) { errCh <- err })
	h.wg.Add(1)

	// Close the write end before writing — io.ErrClosedPipe should be suppressed.
	pipeWriter.Close()
	go func() {
		defer h.wg.Done()
		h.writeToPipe(pipeWriter)
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

	h := newTestProcHandle(t, doneCh, func(error) {})

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

	h := newTestProcHandle(t, doneCh, func(error) {})

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
