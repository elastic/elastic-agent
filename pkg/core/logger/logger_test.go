// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func Test_SetLevel(t *testing.T) {
	t.Cleanup(func() { SetLevel(logp.InfoLevel) })

	l, err := NewWithLogpLevel("", logp.ErrorLevel, true)
	require.NoError(t, err)

	require.Equal(t, false, l.Core().Enabled(zapcore.DebugLevel))
	require.Equal(t, false, l.Core().Enabled(zapcore.InfoLevel))
	require.Equal(t, false, l.Core().Enabled(zapcore.WarnLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.ErrorLevel))

	tests := []struct {
		SetLogLevel  logp.Level
		DebugEnabled bool
		InfoEnabled  bool
		WarnEnabled  bool
		ErrEnabled   bool
	}{
		{logp.DebugLevel, true, true, true, true},
		{logp.InfoLevel, false, true, true, true},
		{logp.WarnLevel, false, false, true, true},
		{logp.ErrorLevel, false, false, false, true},
	}

	for _, tc := range tests {
		SetLevel(tc.SetLogLevel)

		require.Equal(t, tc.DebugEnabled, l.Core().Enabled(zapcore.DebugLevel))
		require.Equal(t, tc.InfoEnabled, l.Core().Enabled(zapcore.InfoLevel))
		require.Equal(t, tc.WarnEnabled, l.Core().Enabled(zapcore.WarnLevel))
		require.Equal(t, tc.ErrEnabled, l.Core().Enabled(zapcore.ErrorLevel))
	}
}

func TestNewInMemory(t *testing.T) {
	log, buff := NewInMemory("in_memory", logp.ConsoleEncoderConfig())

	log.Debugw("a debug message", "debug_key", "debug_val")
	log.Infow("a info message", "info_key", "info_val")
	log.Warnw("a warn message", "warn_key", "warn_val")
	log.Errorw("an error message", "error_key", "error_val")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	assert.Len(t, logs, 4, "expected 4 log entries")

	assert.Contains(t, logs[0], "a debug message")
	assert.Contains(t, logs[0], "debug_key")
	assert.Contains(t, logs[0], "debug_val")

	assert.Contains(t, logs[1], "a info message")
	assert.Contains(t, logs[1], "info_key")
	assert.Contains(t, logs[1], "info_val")

	assert.Contains(t, logs[2], "a warn message")
	assert.Contains(t, logs[2], "warn_key")
	assert.Contains(t, logs[2], "warn_val")

	assert.Contains(t, logs[3], "an error message")
	assert.Contains(t, logs[3], "error_key")
	assert.Contains(t, logs[3], "error_val")
}

func TestNewNamedLogger(t *testing.T) {
	const name = "test-component"

	tmp, err := os.MkdirTemp("", "TestNewNamedLogger*")
	require.NoError(t, err)

	topPath, logsPath := paths.Top(), paths.Logs()
	paths.SetTop(tmp)
	paths.SetLogs(filepath.Join(tmp, DefaultLogDirectory))
	t.Cleanup(func() {
		paths.SetTop(topPath)
		paths.SetLogs(logsPath)
	})

	named, err := NewNamedLogger(name, DefaultLoggingConfig(), DefaultEventLoggingConfig())
	require.NoError(t, err)

	named.Info("normal message")
	named.Infow("event message", logp.TypeKey, logp.EventType)
	require.NoError(t, named.Core().Sync())

	t.Run("normal log file", func(t *testing.T) {
		glob := filepath.Join(paths.Home(), DefaultLogDirectory, name+"-*.ndjson")
		matches, err := filepath.Glob(glob)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "normal log file should exist at %s", glob)
		data, err := os.ReadFile(matches[0])
		require.NoError(t, err)
		assert.Contains(t, string(data), "normal message")
		assert.NotContains(t, string(data), "event message")
	})

	t.Run("event log file", func(t *testing.T) {
		glob := filepath.Join(paths.Home(), DefaultLogDirectory, "events", name+"-event-log-*.ndjson")
		matches, err := filepath.Glob(glob)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "event log file should exist at %s", glob)
		data, err := os.ReadFile(matches[0])
		require.NoError(t, err)
		assert.Contains(t, string(data), "event message")
		assert.NotContains(t, string(data), "normal message")
	})

	t.Run("log level change propagates to named logger", func(t *testing.T) {
		t.Cleanup(func() { SetLevel(logp.InfoLevel) })

		base, err := New("", true)
		require.NoError(t, err)

		require.False(t, named.Core().Enabled(zapcore.DebugLevel))
		named.Debug("dropped debug")

		SetLevel(logp.DebugLevel)
		require.True(t, base.Core().Enabled(zapcore.DebugLevel))
		require.True(t, named.Core().Enabled(zapcore.DebugLevel))

		named.Debug("kept debug")
		require.NoError(t, named.Core().Sync())

		glob := filepath.Join(paths.Home(), DefaultLogDirectory, name+"-*.ndjson")
		matches, err := filepath.Glob(glob)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "log file should exist at %s", glob)
		data, err := os.ReadFile(matches[0])
		require.NoError(t, err)
		assert.Contains(t, string(data), "kept debug")
		assert.NotContains(t, string(data), "dropped debug")
	})
}
